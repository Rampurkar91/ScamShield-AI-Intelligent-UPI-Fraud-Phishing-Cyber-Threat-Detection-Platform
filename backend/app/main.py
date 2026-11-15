from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager
from io import BytesIO
import jwt
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel, EmailStr, Field
from pwdlib import PasswordHash
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session
from PIL import Image, UnidentifiedImageError
from .config import settings
from .db import engine, get_db
from .models import User, Scan
from .scanners import analyze
from .image_scan import analyze_image
from .threat_intelligence import enrich_url

@asynccontextmanager
async def lifespan(app):
    try:
        with engine.connect() as conn: conn.execute(text('SELECT 1'))
    except SQLAlchemyError as exc:
        raise RuntimeError('Database connection failed; check DATABASE_URL and database availability') from exc
    yield

app = FastAPI(title='ScamShield AI', lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=[x.strip().rstrip('/') for x in settings.frontend_url.split(',')], allow_credentials=True, allow_methods=['GET','POST'], allow_headers=['Authorization','Content-Type'])
passwords = PasswordHash.recommended()
# Equalize the expensive hash check for unknown accounts.
_dummy_hash = passwords.hash("not-a-real-account-password")
bearer = HTTPBearer(auto_error=False)
class Credentials(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
class ScanRequest(BaseModel):
    kind: str
    text: str = Field(min_length=1, max_length=30000)
    external_lookup: bool = False

def current_user(auth: HTTPAuthorizationCredentials = Depends(bearer), db: Session = Depends(get_db)):
    try:
        if not auth: raise ValueError()
        payload = jwt.decode(auth.credentials, settings.jwt_secret_key, algorithms=['HS256'], options={'require': ['exp', 'sub']})
        user = db.get(User, int(payload['sub']))
        if not user: raise ValueError()
        return user
    except (jwt.PyJWTError, ValueError, KeyError, TypeError):
        raise HTTPException(401, 'Invalid or expired session')

@app.get('/health')
def health():
    try:
        with engine.connect() as conn: conn.execute(text('SELECT 1'))
        return {'status': 'ok', 'database': 'connected'}
    except SQLAlchemyError:
        raise HTTPException(503, 'Database unavailable')

@app.post('/api/register', status_code=201)
def register(body: Credentials, db: Session = Depends(get_db)):
    user = User(email=body.email.lower(), password_hash=passwords.hash(body.password))
    db.add(user)
    try: db.commit()
    except IntegrityError:
        db.rollback(); raise HTTPException(409, 'Account already exists')
    return {'message': 'Account created'}

@app.post('/api/login')
def login(body: Credentials, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == body.email.lower()).with_for_update())
    valid = passwords.verify(body.password, user.password_hash if user else _dummy_hash)
    if not user:
        raise HTTPException(401, 'Invalid credentials')
    now = datetime.now(timezone.utc)
    locked = user.locked_until
    if locked and locked.tzinfo is None:  # SQLite returns naive UTC timestamps
        locked = locked.replace(tzinfo=timezone.utc)
    if locked and locked > now:
        raise HTTPException(401, 'Invalid credentials or account temporarily locked')
    if not valid:
        user.login_failures += 1
        if user.login_failures >= 5:
            user.locked_until = now + timedelta(minutes=15)
            user.login_failures = 0
        db.commit()
        raise HTTPException(401, 'Invalid credentials or account temporarily locked')
    user.login_failures = 0
    user.locked_until = None
    db.commit()
    token = jwt.encode({'sub': str(user.id), 'exp': datetime.now(timezone.utc) + timedelta(hours=8)}, settings.jwt_secret_key, algorithm='HS256')
    return {'access_token': token, 'token_type': 'bearer'}

@app.get('/api/me')
def me(user: User = Depends(current_user)):
    return {'email': user.email}

def save_scan(db, user, kind, result):
    scan = Scan(user_id=user.id, kind=kind, result=result)
    db.add(scan); db.commit(); db.refresh(scan)
    return {'id': scan.id, 'kind': kind, 'created_at': scan.created_at, 'result': result}

@app.post('/api/scans')
def scan(body: ScanRequest, user: User = Depends(current_user), db: Session = Depends(get_db)):
    try: result = analyze(body.kind, body.text)
    except ValueError: raise HTTPException(400, 'Unsupported scan type')
    if body.kind == 'url':
        result = enrich_url(result, body.text, body.external_lookup)
    return save_scan(db, user, body.kind, result)

@app.post('/api/scans/image')
async def scan_image(file: UploadFile = File(...), user: User = Depends(current_user), db: Session = Depends(get_db)):
    data = await file.read(5 * 1024 * 1024 + 1)
    if len(data) > 5 * 1024 * 1024: raise HTTPException(413, 'Image exceeds 5 MB')
    try:
        with Image.open(BytesIO(data)) as image:
            if image.width * image.height > 20_000_000: raise HTTPException(413, 'Image dimensions are too large')
            image.verify()
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError): raise HTTPException(400, 'Invalid image')
    try:
        result = await run_in_threadpool(analyze_image, data)
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError):
        raise HTTPException(400, 'Invalid image')
    return save_scan(db, user, 'image', result)

@app.get('/api/scans')
def history(user: User = Depends(current_user), db: Session = Depends(get_db)):
    scans = db.scalars(select(Scan).where(Scan.user_id == user.id).order_by(Scan.id.desc()).limit(100)).all()
    return [{'id': s.id, 'kind': s.kind, 'created_at': s.created_at, 'result': s.result} for s in scans]

@app.get('/api/scans/{scan_id}')
def report(scan_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    s = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id))
    if not s: raise HTTPException(404, 'Scan not found')
    return {'id': s.id, 'kind': s.kind, 'created_at': s.created_at, 'result': s.result}
