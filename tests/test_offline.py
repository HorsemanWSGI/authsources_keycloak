"""Actions against a faked admin client: no Keycloak server needed."""
import json
from types import SimpleNamespace as NS

import pytest
from authsources.errors import MagicLinkError, UserExists
from keycloak.exceptions import KeycloakPostError

from authsources_keycloak import actions


def bound(action, admin):
    return action(NS(admin=admin))


def response(status, body=None, text=""):
    def as_json():
        if body is None:
            raise ValueError("no json")
        return body
    return NS(status_code=status, json=as_json, text=text)


def connection(answer, posted):
    def raw_post(path, data):
        posted.update(path=path, json=json.loads(data))
        return answer
    return NS(realm_name="realm", client_id="portal", raw_post=raw_post)


def test_magic_link_uses_the_connection_client():
    posted = {}
    admin = NS(connection=connection(
        response(200, {"link": "https://kc/link"}), posted))

    link = bound(actions.MagicLink, admin).create_magic_link(
        "a@x.de", "https://app/x", ttl=60)

    assert link == "https://kc/link"
    assert posted["path"] == "realms/realm/magic-link"
    assert posted["json"] == {
        "email": "a@x.de",
        "client_id": "portal",
        "redirect_uri": "https://app/x",
        "expiration_seconds": 60,
        "force_create": False,
        "send_email": False,
    }


def test_magic_link_default_ttl():
    posted = {}
    admin = NS(connection=connection(response(200, {"link": "l"}), posted))
    bound(actions.MagicLink, admin).create_magic_link("a@x.de", "https://x")
    assert posted["json"]["expiration_seconds"] == actions.MagicLink.ttl


@pytest.mark.parametrize("answer, detail", [
    (response(404, text="HTTP 404 Not Found"), "HTTP 404 Not Found"),
    (response(404, {"error": "User not found"}), "User not found"),
    (response(502, text="Bad Gateway"), "Bad Gateway"),
])
def test_magic_link_error(answer, detail):
    admin = NS(connection=connection(answer, {}))
    with pytest.raises(MagicLinkError) as exc:
        bound(actions.MagicLink, admin).create_magic_link("a@x.de", "https://x")
    assert exc.value.detail == detail
    assert exc.value.status == answer.status_code


def user():
    return {"username": "a", "password": "secret", "email": "a@x.de"}


def refusing(code, body):
    def create_user(data, exist_ok):
        raise KeycloakPostError(
            error_message=body, response_code=code, response_body=body)
    return NS(create_user=create_user)


@pytest.mark.parametrize("body, field", [
    (b'{"errorMessage":"User exists with same email"}', "email"),
    (b'{"errorMessage":"User exists with same username"}', "username"),
])
def test_create_conflict_is_a_neutral_error(body, field):
    with pytest.raises(UserExists) as exc:
        bound(actions.Create, refusing(409, body)).create(user())
    assert exc.value.field == field


def test_create_other_errors_pass_through():
    with pytest.raises(KeycloakPostError):
        bound(actions.Create, refusing(500, b"boom")).create(user())


def test_create_passes_extra_properties():
    created = []
    admin = NS(create_user=lambda data, exist_ok: created.append(data))
    assert bound(actions.Create, admin).create(
        {**user(), "groups": ["temporary"], "attributes": {"k": ["v"]}})
    assert created == [{
        "username": "a", "email": "a@x.de",
        "credentials": [{"value": "secret", "type": "password"}],
        "groups": ["temporary"], "attributes": {"k": ["v"]},
    }]
