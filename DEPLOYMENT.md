# Deployment and local setup

This prototype is configured for one Vercel frontend, one Render web service and one Render PostgreSQL database. **The hosted integration and PostgreSQL deployment have not been verified**; see limitations in README before use. Provider plan availability and billing may change.

## 1. Push to GitHub

Push this repository's current branch to GitHub and ensure your chosen branch contains `frontend/`, `backend/` and the root `render.yaml`. Never upload `.env` files or credentials. The example files are safe templates, not valid secrets.

## 2. Deploy database and API on Render

1. In the Render dashboard, choose **New → Blueprint**, connect GitHub and select the repository and branch. Render discovers the root `render.yaml` and proposes a Python web service and managed PostgreSQL database. Review plan, region, availability, pricing and database retention before creating them. The free database plan may expire; use a persistent paid plan for important data.
2. When prompted for `FRONTEND_URL`, enter an HTTPS origin. If the Vercel URL is not yet known, use a temporary HTTPS origin such as `https://example.com`; replace it in step 4. Render creates `JWT_SECRET_KEY` and injects the database internal connection string; do not share either. Keep the generated secret stable across deployments or existing tokens will stop working.
3. The Blueprint sets root directory `backend`, build `pip install -r requirements.txt`, start `alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port $PORT`, and health path `/health`. Migrations run before startup and do not drop data on upgrade. For scaled deployments, run migrations as a single release step instead of concurrently from multiple instances, after backing up and reviewing migration changes. If creating services manually, replicate these settings and set `DATABASE_URL`, `JWT_SECRET_KEY`, `ENVIRONMENT=production` and `FRONTEND_URL` in the service's Environment page.
4. Wait for deployment; visit `https://YOUR-API.onrender.com/health` and `/docs`. A 503 health response or a failed startup indicates a database problem; check Render logs and the database status. Ensure web service and database are in the same region for the internal URL. For external PostgreSQL use the provider's SSL-enabled URL (e.g. `?sslmode=require`); do not disable TLS when required.

## 3. Deploy frontend on Vercel

1. In Vercel choose **Add New → Project**, import the same GitHub repository and branch.
2. Set **Root Directory** to `frontend`, framework preset to Vite, build command `npm run build`, output directory `dist`. `frontend/vercel.json` rewrites SPA paths to the entry point.
3. Add `VITE_API_BASE_URL` with the Render HTTPS service origin, e.g. `https://YOUR-API.onrender.com` (no `/api` suffix). This is public browser configuration, never a secret. Deploy. After changing a Vite environment variable, redeploy so it is included at build time.

## 4. Connect the deployments

In Render's web service, go to **Environment**, set `FRONTEND_URL` to the exact Vercel HTTPS origin, without a path or trailing slash, and save/redeploy. Comma-separated origins are supported if needed. Do not use `*` for authenticated requests. Vercel preview deployments have different origins and need explicit inclusion. Verify `/health` again and test the browser; a CORS error usually means the origin does not match exactly.

## 5. Verify

Register and sign in, scan a URL and a suspicious message, upload a screenshot, check history and print/save a report, refresh the page, then log out. Confirm that screenshot results show QR and OCR check status and limitations. An image with no readable QR or OCR text has an unknown risk. Try from a second account to verify history isolation. Check Render logs and browser developer tools for errors. These are manual hosted checks, not a claim that they have already passed.

## Local development

From the repository root, create and activate a Python virtual environment and install dependencies:

```sh
python -m venv .venv
# Linux/macOS; on Windows use .venv\\Scripts\\activate
source .venv/bin/activate
pip install -r backend/requirements.txt
cd backend
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
# Replace JWT_SECRET_KEY in .env with the generated value.
alembic upgrade head
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

In another terminal:

```sh
cd frontend
npm install
cp .env.example .env
npm run dev
```

Open `http://localhost:5173`. The example frontend URL accesses the backend directly; alternatively set `VITE_API_BASE_URL=` to use the Vite development proxy. SQLite is provided only for local development. Production requires PostgreSQL. The backend reads `.env` from its working directory. To run migrations manually use `cd backend && alembic upgrade head`; back up production data first. Never run downgrade casually.

## Configuration and troubleshooting

Required backend variables: `DATABASE_URL`, `JWT_SECRET_KEY` (at least 32 characters, securely generated), `FRONTEND_URL` (exact browser origin), and `ENVIRONMENT=production` on Render. Frontend: `VITE_API_BASE_URL` for deployed builds. Optional backend-only keys are `GOOGLE_SAFE_BROWSING_API_KEY` and `VIRUSTOTAL_API_KEY`. Neither is required for local scanning. Users must opt in per URL scan; the full URL (or its reversible URL identifier for VirusTotal) is sent to the configured providers. Do not submit confidential links. API provider terms, quotas, privacy policies and Google Safe Browsing usage restrictions apply. The VirusTotal integration only looks up existing reports and does not submit URLs for scanning. Non-URL scans are local. Secrets must remain backend-only. SSL options are specified in the database URL when required.

- **API fails to start:** inspect service logs for missing configuration, an invalid secret, unreachable database or failed migration. Run `alembic upgrade head` against the correct database; don't delete data to fix a migration.
- **CORS or network failure:** check exact `FRONTEND_URL`, HTTPS and `VITE_API_BASE_URL`, and redeploy after changes. Free services may take time to wake.
- **Refresh/404:** confirm Vercel root directory is `frontend` and its rewrite configuration was deployed.
- **Session expired:** sign in again. Browser session storage is scoped to the tab; clearing it or logout removes the token.
- **Unknown image result or partial analysis:** QR decoding is included, but OCR requires Tesseract and English language data installed on the host. The standard Render deployment does not install it, so OCR is typically unavailable there. AI is not implemented; URL threat intelligence is optional and requires provider configuration and user consent. No external-provider success is simulated.
- **Database persistence:** ensure the Render managed PostgreSQL URL, not SQLite, is used; review plan expiration, backup and retention settings.

## Optional local OCR

If Tesseract OCR with English language data is already installed and `tesseract` is on the backend PATH, screenshot scanning runs it with a 15-second timeout. Installation is platform-specific and is not required for the normal deployment. Only English is configured; OCR can miss or misread text. QR decoding uses the `zxing-cpp` Python wheel and is included in the standard requirements. Neither QR contents nor OCR text are saved.

## Optional threat intelligence

Set `GOOGLE_SAFE_BROWSING_API_KEY` and/or `VIRUSTOTAL_API_KEY` in the Render web service Environment page, or in local `backend/.env`. Redeploy after changes. The user must check the consent box on each URL scan. Results distinguish match, no match, not found, unavailable, skipped and not configured. Providers can be unavailable or return no match for a dangerous URL. Local, credential-bearing and obviously private URLs are skipped as a precaution; this filter cannot identify all sensitive URLs. Never submit private links. Google Safe Browsing API usage is subject to Google terms, including restrictions on commercial usage; choose an appropriate service and license. Provider tests are mocked, not live.
