from authsources_keycloak.source import KeycloakSource
from authsources_keycloak import actions as keycloak_actions
from authsources.abc.actions import Create, Getter
from keycloak.keycloak_admin import KeycloakAdmin


def test_source(connection):
    source = KeycloakSource(
        connection,
        title="Keycloak",
        description="Test Keycloak Source"
    )
    assert isinstance(source.admin, KeycloakAdmin)


def test_source_create(connection):
    source = KeycloakSource(
        connection,
        title="Keycloak",
        description="Test Keycloak Source",
        actions=(
            keycloak_actions.Create,
            keycloak_actions.Fetch
        )
    )

    create = source[Create]
    assert create is not None
    assert create({})
