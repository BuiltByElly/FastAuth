# AGENTS.md — working in this repo

## Commands

```bash
uv sync --group dev          # install (Python 3.14+)
uv run pytest tests/ -q      # full suite; needs redis at localhost:6379 (redis tests skip without it)
```

`pytest.ini`: `asyncio_mode = auto` — plain `async def test_...` works, no decorators. SQLite tests use per-test files (`db_url` fixture); redis tests use DB 15 with `flushdb`.

## Layout

`src/fastauth/` — `core.py` (auth classes), `config.py` (frozen `FastAuthConfig`), `adapters/` (ABCs + sqlalchemy + rate_limit backends), `routes/` (+ `context.py`), `oauth/` (provider clients), `dependencies/` (`current_user`, `rate_limiter`), `hooks/`, `schemas.py`, `types.py` (import-cycle breaker), `security.py`, `cookies.py`, `protocols.py`. Details: `ARCHITECTURE.md`. Examples: `examples/{basic,jwt_example,oidc,oauth2}/`. Docs: `docs/` via `zensical.toml` (`uvx zensical serve`); `docs/ARCHITECTURE.md` mirrors the root copy — keep both in sync.

## Invariants

- Async-only. Type hints on everything; direct no-fluff docstrings.
- Adapters flush, routes commit. Only the rate limiter commits inside `check()` (dependency ordering).
- `expire_on_commit=False` on all session factories.
- Config models frozen; bad values raise at startup, never in production.
- Hooks: before-hooks `(payload, request) -> payload`, `HookAbort` to block, crash → 500. Observers return `None`, run post-response, never raise (log to `fastauth` logger). Passwords only to before-hooks as `SecretStr`.
- `OAuthStateManager` is shared by OIDC + OAuth2 — don't duplicate its tests per strategy.
- `OIDCAuth`/`OAuth2Auth` skip `FastAuth.__init__` (no password machinery on OAuth paths).

## Tests (`tests/`)

`unit/` (guards, backends, wiring), `integration/` (HTTP flows), `security/` (attack surface). `tests/conftest.py` owns builders (`build_*_app`), provider stubs (`stub_oidc_provider`, `stub_oauth2_provider`), and `*_begin` helpers — reuse them. Stub providers at the class level; nothing hits the network. Prune non-core/duplicate tests; cover core paths once per strategy. Async fixtures + `TestClient` in one test need loop care (asyncio connections can't cross the portal loop — see the redis fixture in `test_rate_limit_routes.py`).

## Docs

Examples-first: quote `examples/`, never invent untested snippets. Public/Shared behavior goes in `docs/` + `llms.txt`; keep `llms.txt` in sync when strategies, hooks, config, or error semantics change.
