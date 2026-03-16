"""Currently untested module."""

import typing as t
from keycloak import KeycloakOpenID, KeycloakAdmin, KeycloakOpenIDConnection
from keycloak.exceptions import KeycloakAuthenticationError
from authsources.abc import source, actions
from authsources.abc.identity import User, UserID
from authsources.json import JSONSchema
from authsources.abc.protocols import RequestProtocol


class KeycloakData(t.TypedDict, total=False):
    username: str
    email: str
    groups: t.NotRequired[list[str]]


class KeycloakUser(User):
    data: KeycloakData

    def __init__(self, id: UserID, data: KeycloakData):
        self.id = id
        self.data = data


class KeycloakSource(source.Source):

    admin: KeycloakAdmin
    connector: KeycloakOpenID
    config: dict

    def __init__(self,
                 connection: KeycloakOpenIDConnection,
                 *,
                 title: str,
                 description: str,
                 usertype: t.Type[KeycloakUser] = KeycloakUser,
                 config: dict | None = None,
                 bindings: t.Mapping | None = None,
                 actions: t.Iterable[source.SourceAction] | None = None):
        self.connector = connection.keycloak_openid
        self.admin = KeycloakAdmin(connection=connection)
        self.public_key = (
            "-----BEGIN PUBLIC KEY-----\n"
            + self.connector.public_key()
            + "\n-----END PUBLIC KEY-----"
        )
        self.title = title
        self.description = description
        self.bindings = bindings if bindings is not None else {}
        self.usertype = usertype
        self.config = config if config is not None else {}
        self.define(actions)

    def decode_token(self, token: str):
        return self.connector.decode_token(
            token=token,
            key=self.public_key,
            validate=False
        )
