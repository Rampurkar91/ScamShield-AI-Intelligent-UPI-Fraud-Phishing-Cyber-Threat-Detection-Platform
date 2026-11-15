import os
os.environ['DATABASE_URL'] = 'sqlite:///./test_scams.db'
os.environ['JWT_SECRET_KEY'] = 'test-secret-' + 'x' * 40
os.environ['FRONTEND_URL'] = 'http://localhost:5173'
from fastapi.testclient import TestClient
from app.main import app
from app.db import Base, engine
from app.scanners import analyze

Base.metadata.drop_all(engine)
Base.metadata.create_all(engine)

def test_flows():
    with TestClient(app) as client:
        assert client.get('/health').json()['database'] == 'connected'
        assert client.get('/docs').status_code == 200
        cors = client.options('/api/scans', headers={'Origin':'http://localhost:5173','Access-Control-Request-Method':'POST'})
        assert cors.headers['access-control-allow-origin'] == 'http://localhost:5173'
        account = {'email':'test@example.com','password':'strong-password'}
        assert client.post('/api/register', json=account).status_code == 201
        assert client.post('/api/login', json={**account, 'password':'wrong-password'}).status_code == 401
        token = client.post('/api/login', json=account).json()['access_token']
        headers = {'Authorization':'Bearer '+token}
        assert client.get('/api/me', headers=headers).json()['email'] == account['email']
        assert client.post('/api/scans', json={'kind':'url','text':'http://192.0.2.1/?otp=1'}, headers=headers).json()['result']['score'] > 0
        assert client.post('/api/scans', json={'kind':'message','text':'Urgent! Share your OTP for refund'}, headers=headers).json()['result']['score'] > 0
        image = client.post('/api/scans/image', files={'file':('test.png',b'not an image','image/png')}, headers=headers)
        assert image.status_code == 400
        from io import BytesIO
        from PIL import Image
        buf = BytesIO(); Image.new('RGB', (10,10)).save(buf, format='PNG')
        image = client.post('/api/scans/image', files={'file':('test.png',buf.getvalue(),'image/png')}, headers=headers)
        assert image.json()['result']['score'] is None
        scans = client.get('/api/scans',headers=headers).json()
        assert len(scans) == 3
        assert client.get('/api/scans/'+str(scans[0]['id']),headers=headers).status_code == 200
        assert client.get('/api/scans').status_code == 401
        other = {'email':'other@example.com','password':'strong-password'}
        client.post('/api/register', json=other)
        other_token = client.post('/api/login', json=other).json()['access_token']
        assert client.get('/api/scans/'+str(scans[0]['id']),headers={'Authorization':'Bearer '+other_token}).status_code == 404

def test_rules():
    assert analyze('upi','Approve collect request and share UPI PIN')['score'] >= 60
    assert analyze('email','From: a@example.com\nReply-To: b@evil.com')['score'] > 0
    assert analyze('code','password = "verysecretpassword"')['score'] > 0

def test_qr_analysis():
    from io import BytesIO
    from PIL import Image
    import zxingcpp
    from app.image_scan import analyze_image
    for content, indicator in [('upi://pay?pa=test@bank&am=100', 'UPI payment QR code'), ('http://192.0.2.1', 'IP address host')]:
        qr = zxingcpp.write_barcode(zxingcpp.BarcodeFormat.QRCode, content, width=256, height=256)
        shape = memoryview(qr).shape
        image = Image.frombuffer('L', (shape[1], shape[0]), qr, 'raw', 'L', 0, 1)
        buf = BytesIO(); image.save(buf, format='PNG')
        result = analyze_image(buf.getvalue())
        assert result['checks']['qr'] == 'completed'
        assert any(item['name'] == indicator for item in result['indicators'])
        assert result['status'] == 'partial'

def test_login_lockout():
    with TestClient(app) as client:
        account = {'email':'locked@example.com', 'password':'strong-password'}
        assert client.post('/api/register', json=account).status_code == 201
        for _ in range(5):
            assert client.post('/api/login', json={**account, 'password':'wrong-password'}).status_code == 401
        assert client.post('/api/login', json=account).status_code == 401

def test_optional_ocr(monkeypatch):
    from io import BytesIO
    from types import SimpleNamespace
    from PIL import Image
    from app import image_scan
    buf = BytesIO(); Image.new('RGB', (10, 10)).save(buf, format='PNG')
    monkeypatch.setattr(image_scan.shutil, 'which', lambda _: '/usr/bin/tesseract')
    monkeypatch.setattr(image_scan.subprocess, 'run', lambda *a, **k: SimpleNamespace(stdout=b'Urgent share your OTP'))
    result = image_scan.analyze_image(buf.getvalue())
    assert result['checks']['ocr'] == 'completed'
    assert any(i['name'] == 'Sensitive credential request' for i in result['indicators'])
    def fail(*args, **kwargs):
        raise image_scan.subprocess.TimeoutExpired('tesseract', 15)
    monkeypatch.setattr(image_scan.subprocess, 'run', fail)
    result = image_scan.analyze_image(buf.getvalue())
    assert result['score'] is None
    assert any('timed out' in s for s in result['limitations'])
