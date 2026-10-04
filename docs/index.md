# FastAuth

Simple and flexible authentication library for FastAPI — FastAPI-only by design.

Session, JWT, OIDC, and plain OAuth2 strategies. One class per strategy, one config object, your own SQLAlchemy or any ORM models. Asynchronous end to end.

Here's a quick example using SessionAuth - a class for the session authentication strategy:
```python
auth = SessionAuth(
    adapter=SQLAlchemySessionAdapter,
    user_model=User,
    session_model=Session,
    db_session_dependency=get_db,
)
app.include_router(auth.router)
```

Start with [Quickstart](getting-started/quickstart.md). Full signatures in the [API reference](reference/api.md); internals in `ARCHITECTURE.md` at the repo root.
