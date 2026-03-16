import pytest
from authsources_keycloak.source import KeycloakSource, KeycloakUser
from authsources_keycloak import actions as keycloak_actions
from authsources.protocols import Create, Getter, Delete, Groups
from authsources.protocols import GroupCreate, GroupDelete, GroupManage
from keycloak.keycloak_admin import KeycloakAdmin
from authsources.json import ValidationErrors


def test_source(connection):
    source = KeycloakSource(
        connection,
        title="Keycloak",
        description="Test Keycloak Source"
    )
    assert isinstance(source.admin, KeycloakAdmin)


def test_source_create_delete(connection):
    source = KeycloakSource(
        connection,
        title="Keycloak",
        description="Test Keycloak Source",
        actions=(
            keycloak_actions.Create,
            keycloak_actions.Fetch,
            keycloak_actions.Delete,
        )
    )

    # Create
    assert Create in source

    action = source[Create]
    assert action is not None
    with pytest.raises(ValidationErrors) as exc:
        action.create({})

    result = action.create({
        "username": "test",
        "password": "test",
        "email": "tester@test.com"
    })
    assert result is True

    # Fetch
    assert Getter in source

    action = source[Getter]
    assert action is not None
    user = action.get("test")
    assert isinstance(user, KeycloakUser)

    # Delete
    assert Delete in source
    action = source[Delete]
    assert action is not None
    result = action.delete('test')
    assert result is True


def test_source_group_list(connection):
    source = KeycloakSource(
        connection,
        title="Keycloak",
        description="Test Keycloak Source",
        actions=(
            keycloak_actions.Groups,
        )
    )

    assert Groups in source

    action = source[Groups]
    #assert action is not None
    groups = action.list_groups()
    assert len(groups) == 1
    assert groups[0]['name'] == 'test_group'


def test_source_group_create_delete(connection):
    source = KeycloakSource(
        connection,
        title="Keycloak",
        description="Test Keycloak Source",
        actions=(
            keycloak_actions.GroupCreate,
            keycloak_actions.GroupDelete,
            keycloak_actions.Groups,
        )
    )

    # Create
    assert GroupCreate in source

    action = source[GroupCreate]
    assert action is not None
    with pytest.raises(ValidationErrors) as exc:
        action.create_group({})

    result = action.create_group({
        "name": "mygroup",
    })
    assert result is True

    # Fetch
    assert Groups in source

    action = source[Groups]
    #assert action is not None
    groups = action.list_groups()
    assert len(groups) == 2

    # Delete
    assert GroupDelete in source
    action = source[GroupDelete]
    assert action is not None
    result = action.delete_group('mygroup')
    assert result is True
