# ScamShield AI

A monorepo starter for examining suspicious links, messages, UPI requests, email headers and code snippets. A React/Vite interface connects to a FastAPI service, with SQLAlchemy, Alembic and PostgreSQL for accounts and scan history. See [DEPLOYMENT.md](DEPLOYMENT.md) for local setup, Render and Vercel instructions, verification and troubleshooting.

## What works and what does not

- Local, explainable heuristics check URL structure, message patterns (including some Hindi keywords), common UPI scams, reply-to mismatch and selected code patterns. Scores are not calibrated probabilities and a low score is not a safety guarantee. We do not visit URLs or verify certificates. Optional, explicitly opted-in URL lookups query Google Safe Browsing and existing VirusTotal reports; provider failures do not stop local analysis.
- Image uploads decode QR codes locally and analyze their contents without visiting links. English OCR runs only when the optional Tesseract executable is installed; otherwise it is marked unavailable. If neither QR nor text is extracted, the risk is unknown. Results remain partial and may miss content. AI, Gemini, SMTP, dependency vulnerability checks and repository scanning are not implemented. Google Safe Browsing and VirusTotal keys are optional; URL lookups require user opt-in. No API keys are required for local rules.
- Users can register, sign in, view their own history and print a report. Raw scan inputs and uploaded images are not stored, but results are stored in the database. Session tokens are stored in browser session storage for eight hours; they survive refresh but logout only removes the local token, not already issued tokens.
- This is a prototype, **not production-ready**. It has a database-backed temporary lockout after five failed logins, but lacks IP-based rate limiting, email verification, password reset, token revocation, comprehensive security hardening and the advanced detection integrations requested. Account lockouts can be abused for denial of service. Do not use it for sensitive data or as a sole fraud decision system.

## Layout

`frontend/` contains the Vite app and Vercel SPA rewrite. `backend/` contains the API, heuristic scanner, tests and migrations. The root `render.yaml` is a Render Blueprint for the API and managed PostgreSQL. There is no Docker, worker or Redis requirement.

## Tests

After setup, run `cd backend && ../.venv/bin/python -m pytest -q` and `cd frontend && npm run build`. Tests use SQLite and do not establish production PostgreSQL or hosted deployment readiness.
