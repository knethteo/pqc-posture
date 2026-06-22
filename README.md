# PQC Posture

Post-Quantum Cryptography readiness dashboard for Tenable Vulnerability Management (Tenable.io).

## Quick start

```bash
pip install -r requirements.txt
cp .env.example .env   # then fill in your Tenable API keys
uvicorn main:app --reload --port 8000
```

Open http://localhost:8000

If you don't have API keys in `.env`, the app will redirect you to the in-app setup page at http://localhost:8000/setup.

## Docker

```bash
docker build -t pqc-posture .
docker run -p 8000:8000 --env-file .env pqc-posture
```

## API keys

Keys are read from environment variables `TIO_ACCESS_KEY` / `TIO_SECRET_KEY` (via `.env` or Docker `--env-file`).  
You can also enter them via the in-app setup page — they are stored locally in `.tio_keys` (gitignored) and never sent to the browser.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Fleet overview (Page 1) |
| GET | `/asset?uuid=<uuid>` | Asset detail (Page 2) |
| GET | `/setup` | API key setup |
| GET | `/api/pqc-assets` | JSON: all at-risk assets |
| GET | `/api/asset/{uuid}` | JSON: full PQC detail for one asset |
| GET | `/api/status` | JSON: whether keys are configured |
| POST | `/api/auth` | Set API keys at runtime |

## PQC plugin set

Configured in `main.py` as `PLUGINS` — a single dict grouped by category. Edit it there to add/remove plugin IDs.

## Caching

Workbench calls are cached in memory for 10 minutes. Cache is cleared when new API keys are set. Restart the server to force a full refresh.

## Data source

All findings are sourced from Tenable Vulnerability Management via the Workbench API. No data is fabricated. Truncated plugin outputs are flagged with a link to the Tenable console.
