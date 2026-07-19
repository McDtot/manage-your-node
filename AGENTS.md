# AGENTS.md

## Cursor Cloud specific instructions

Manage Your Node is a single self-hosted Python web app (Starlette + Uvicorn, SQLite embedded). There is one deployable service; the proxy data plane lives on remote VPS machines managed over SSH and is not runnable locally. Standard commands live in `README.md` (see "本地开发").

Key facts for running/testing locally:

- Python 3.12 is required. The dependency-refresh update script keeps a project virtualenv at `.venv/`; activate it with `. .venv/bin/activate` before running anything.
- Run the dev server: `python -m app.server`. It serves the UI + API on `http://127.0.0.1:8787`.
- Binding to a loopback `HOST` (e.g. `127.0.0.1`) auto-enables insecure/dev mode, so `APP_SECRET`/`ADMIN_PASSWORD` are NOT required to start. If unset, the admin password falls back to the app secret (`development-only-secret`). For a predictable login, export `ADMIN_USERNAME`, `ADMIN_PASSWORD`, and `APP_SECRET` before starting. Do NOT set `APP_ALLOW_INSECURE=1` together with a non-loopback `HOST` — startup will refuse.
- Health checks (no auth): `GET /api/health/live` and `GET /api/health/ready` (the latter pings SQLite).
- Write API calls (`POST`/`PATCH`/`DELETE` under `/api/`) require both a session cookie and CSRF: send the `X-CSRF-Token` header matching the `myn_csrf` cookie, and an `Origin` header equal to the request origin. On loopback the cookies are named `myn_session` / `myn_csrf` (no `__Host-` prefix, since cookies are not `Secure` over HTTP).
- The SQLite DB is created automatically under `data/manage_node.db` (gitignored). Delete `data/` to reset state.
- Tests: `pytest` (config in `pytest.ini`, suite under `tests/`). Tests mock SSH / 3x-ui, so no external services or network are needed.
- There is no configured linter/formatter in this repo (dev deps are only `pytest` + `httpx2`); `# noqa` markers in the source are not enforced by any bundled tool.
- Full product E2E (deploying 3x-ui, creating proxy users/chains) requires real SSH-accessible VPS hosts and is out of scope for local dev; only the panel + API can be exercised locally.
