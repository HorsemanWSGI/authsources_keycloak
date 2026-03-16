import pytest
from keycloak import KeycloakOpenIDConnection


@pytest.fixture(scope="session")
def connection():
    return KeycloakOpenIDConnection(
        server_url="http://localhost:8085/auth",
        client_id="test-admin",
        client_secret_key="j1eoG9Ot7oNwlijwuBHii9qfWhzw3Vjy",
        realm_name="test-realm"
    )
