# SmartFuzz Backend — AI-Driven Intelligent Web Fuzzer

Production-grade FastAPI backend for SmartFuzz, a final year project that performs AI-guided web application security testing.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Framework | FastAPI (Python 3.12+) |
| Database | PostgreSQL + SQLAlchemy (async) |
| Migrations | Alembic |
| Task Queue | Celery + Redis |
| HTTP Client | httpx (async) |
| Crawler | BeautifulSoup4 + lxml |
| AI | Google Gemini API |
| Auth | JWT (python-jose) + bcrypt |
| Real-Time | WebSockets |
| Validation | Pydantic v2 |
| Logging | structlog |
| Containerization | Docker + Docker Compose |

---

## Project Structure

```
smartfuzz-backend/
├── app/
│   ├── main.py                  # FastAPI app entry point
│   ├── api/
│   │   └── routes/
│   │       ├── auth.py          # Auth endpoints
│   │       ├── targets.py       # Target management
│   │       ├── scans.py         # Scan orchestration
│   │       ├── payloads.py      # AI payload generation
│   │       ├── fuzz.py          # Fuzzing engine routes
│   │       ├── reports.py       # Report generation
│   │       └── websockets.py    # WebSocket endpoints
│   ├── core/
│   │   ├── config.py            # Settings (env vars)
│   │   ├── security.py          # JWT, hashing
│   │   ├── dependencies.py      # DI: DB, current user
│   │   └── logging.py           # structlog setup
│   ├── db/
│   │   ├── base.py              # SQLAlchemy base
│   │   ├── session.py           # Async session factory
│   │   └── init_db.py           # DB initialization
│   ├── models/                  # SQLAlchemy ORM models
│   │   ├── user.py
│   │   ├── target.py
│   │   ├── scan.py
│   │   ├── endpoint.py
│   │   ├── payload.py
│   │   ├── vulnerability.py
│   │   └── report.py
│   ├── schemas/                 # Pydantic schemas
│   │   ├── auth.py
│   │   ├── target.py
│   │   ├── scan.py
│   │   ├── payload.py
│   │   ├── vulnerability.py
│   │   └── report.py
│   ├── services/
│   │   ├── ai/
│   │   │   ├── gemini_client.py     # Gemini API wrapper
│   │   │   └── payload_engine.py    # AI payload generation
│   │   ├── crawler/
│   │   │   ├── crawler.py           # Async BFS web crawler
│   │   │   └── parser.py            # HTML form/link parser
│   │   ├── fuzzer/
│   │   │   ├── engine.py            # Core fuzzing engine
│   │   │   ├── detector.py          # Vulnerability detector
│   │   │   └── payloads/            # Static payload libraries
│   │   │       ├── sqli.py
│   │   │       ├── xss.py
│   │   │       ├── rce.py
│   │   │       └── auth_bypass.py
│   │   └── reporting/
│   │       ├── report_builder.py    # JSON/PDF report generator
│   │       └── pdf_generator.py     # PDF export
│   ├── websockets/
│   │   └── manager.py           # WebSocket connection manager
│   └── utils/
│       ├── url_validator.py     # URL sanitization + SSRF prevention
│       └── rate_limiter.py      # Request rate limiter
├── alembic/                     # DB migrations
├── tests/                       # Test suite
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
├── scripts/
│   └── seed_db.py
├── .env.example
├── requirements.txt
├── alembic.ini
└── README.md
```

---

## Quick Start

### 1. Clone & Install

```bash
git clone <repo>
cd smartfuzz-backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your credentials
```

### 3. Start Services (Docker)

```bash
docker-compose up -d postgres redis
```

### 4. Run Migrations

```bash
alembic upgrade head
```

### 5. Start Backend

```bash
uvicorn app.main:app --reload --port 8000
```

### 6. Start Celery Worker

```bash
celery -A app.core.celery_app worker --loglevel=info
```

---

## API Documentation

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

---

## Environment Variables

See `.env.example` for all required variables.

Key variables:
- `GEMINI_API_KEY` — Google Gemini API key
- `DATABASE_URL` — PostgreSQL connection string
- `REDIS_URL` — Redis connection string
- `SECRET_KEY` — JWT signing secret
- `FRONTEND_URL` — React frontend URL for CORS

---

## Frontend Integration

The React frontend (SmartFuzz) connects to this backend via:
- REST API at `http://localhost:8000/api/v1/`
- WebSocket at `ws://localhost:8000/ws/scans/{scan_id}`

---

## Security Notes

- All target URLs are validated against SSRF blocklists
- Private IP ranges are blocked from being scanned
- JWT tokens expire after 30 minutes (configurable)
- Rate limiting applied per user per endpoint
- All inputs sanitized via Pydantic validators