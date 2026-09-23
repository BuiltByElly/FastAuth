"""Unit tests: hook runners never leak, never raise (observers), and
pass HookAbort through untouched."""

import pytest
from fastapi import HTTPException, Request
from pydantic import ValidationError

from fastauth.hooks.exceptions import HookAbort
from fastauth.hooks.login import LoginFailure, LoginHooks
from fastauth.hooks.logout import LogoutHooks
from fastauth.hooks.refresh import RefreshHooks
from fastauth.hooks.signup import SignupHooks
from fastauth.schemas import build_login_schema, build_signup_schema


def make_request(path="/auth/signup"):
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": path,
            "headers": [],
            "query_string": b"",
            "server": ("testserver", 80),
            "scheme": "http",
            "client": ("1.2.3.4", 1234),
        }
    )


@pytest.fixture
def signup_hooks():
    return SignupHooks(schema=build_signup_schema({"role": (str, ...)}))


@pytest.fixture
def login_hooks():
    return LoginHooks(schema=build_login_schema())


def _payload(schema, **overrides):
    base = {"email": "u@example.com", "password": "long-enough"}
    base.update(overrides)
    return schema(**base)


async def test_observers_never_raise(signup_hooks, login_hooks):
    async def boom(*args):
        raise RuntimeError("kaboom")

    signup_hooks.on_after_signup(boom)
    signup_hooks.on_signup_failure(boom)
    login_hooks.on_login_failure(boom)
    login_hooks.on_after_login(boom)
    LogoutHooks().add_after_logout(boom)
    RefreshHooks().on_token_reuse_detected(boom)

    await signup_hooks.run_after_signup(object(), make_request())
    await signup_hooks.run_signup_failure("err", make_request())
    await login_hooks.run_login_failure(
        LoginFailure(user_id=None, error="x"), make_request()
    )
    await login_hooks.run_after_login(object(), make_request())
    await LogoutHooks().run_after_logout("uid")
    await RefreshHooks().run_token_reuse_detected("uid", make_request())


async def test_hook_abort_passes_through_untouched(signup_hooks, login_hooks):
    async def deny(payload, request):
        raise HookAbort(418, "teapot")

    signup_hooks.on_before_signup(deny)
    login_hooks.on_before_login(deny)
    schema = signup_hooks._schema
    with pytest.raises(HookAbort) as exc:
        await signup_hooks.run_before_signup(_payload(schema, role="m"), make_request())
    assert (exc.value.status_code, exc.value.detail) == (418, "teapot")
    with pytest.raises(HookAbort) as exc:
        await login_hooks.run_before_login(
            _payload(login_hooks._schema), make_request()
        )
    assert (exc.value.status_code, exc.value.detail) == (418, "teapot")


async def test_before_runners_reject_wrong_types(signup_hooks, login_hooks):
    async def sloppy(payload, request):
        return {"not": "a model"}

    signup_hooks.on_before_signup(sloppy)
    login_hooks.on_before_login(sloppy)
    with pytest.raises(HTTPException) as exc:
        await signup_hooks.run_before_signup(
            _payload(signup_hooks._schema, role="m"), make_request()
        )
    assert exc.value.status_code == 500
    with pytest.raises(HTTPException) as exc:
        await login_hooks.run_before_login(
            _payload(login_hooks._schema), make_request()
        )
    assert exc.value.status_code == 500


async def test_before_runners_crash_generic(signup_hooks):
    async def boom(payload, request):
        raise RuntimeError("kaboom")

    signup_hooks.on_before_signup(boom)
    with pytest.raises(HTTPException) as exc:
        await signup_hooks.run_before_signup(
            _payload(signup_hooks._schema, role="m"), make_request()
        )
    assert exc.value.status_code == 500
    assert exc.value.detail == "Internal error"


def test_login_failure_event_is_frozen():
    failure = LoginFailure(user_id=None, error="x")
    with pytest.raises(ValidationError):
        failure.user_id = "tampered"  # type: ignore[misc]


def test_registration_returns_fn_for_decorator_use(signup_hooks):
    async def handler(payload, request):
        return payload

    assert signup_hooks.on_before_signup(handler) is handler
