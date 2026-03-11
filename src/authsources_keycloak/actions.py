from authsources.abc import source, actions
from authsources.abc.identity import User, UserID
from authsources.json import JSONSchema
from authsources.abc.protocols import RequestProtocol


class Fetch(actions.Getter):

    schema = None

    def get(self, request: RequestProtocol, uid: UserID) -> User | None:
        if kuid := self.source.admin.get_user_id(uid):
            data = self.source.admin.get_user(kuid)
            groups = self.source.admin.get_user_groups(kuid)
            data['groups'] = groups
            user = KeycloakUser(uid, data=data)
            return user



class Preflight(actions.Preflight):

    schema = None

    def preflight(self):
        env_token = self.request.app.config.keycloak.get(
            "header", "HTTP_ACCESS_TOKEN"
        )
        if token := self.request.environ.get(env_token):
            token_info = self.source.decode_token(token=token)
            user = KeycloakUser(
                token_info['preferred_username'],
                data=token_info
            )
            return user


class Search(actions.Search):

    schema = JSONSchema({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "User search",
        "type": "object",
        "properties": {
            "email": {
                "type": "string",
                "description": "User email."
            },
            "username": {
                "type": "string",
                "description": "User username."
            },
        }
    })

    def count(self, criterions: dict) -> int:
        return self.source.admin.users_count({"q": criterions})

    def search(self, criterions: dict, index: int = 0, limit: int = 10):
        print(criterions)
        results = self.source.admin.get_users(
            query={"max": limit, "first": index, **criterions}
        )
        for user in results:
            yield KeycloakUser(user['username'], data=user)


class Challenge(actions.Challenge):

    schema = JSONSchema({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Login",
        "type": "object",
        "properties": {
            "username": {
                "type": "string",
                "description": "User name."
            },
            "password": {
                "type": "string",
                "description": "User password"
            }
        },
        "required": ["username", "password"]
    })

    def challenge(self, credentials: dict) -> User | None:
        errors = list(self.schema.validate(credentials))
        if errors:
            # FixMe
            return None

        try:
            token = self.source.connector.token(
                credentials["username"],
                password=credentials["password"],
                scope="openid",
            )
        except KeycloakAuthenticationError:
            return None

        token_info = self.source.decode_token(token["access_token"])
        user = KeycloakUser(
            credentials["username"],
            token_info,
        )
        return user


class Create(actions.Challenge):

    schema = JSONSchema({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "User",
        "type": "object",
        "properties": {
            "username": {
                "type": "string",
                "description": "User name."
            },
            "email": {
                "type": "string",
                "description": "User email."
            },
            "password": {
                "type": "string",
                "description": "User password"
            }
        },
        "required": ["username", "password", "email"],
    })

    def create(self, data: dict):
        errors = list(self.schema.validate(data))
        if errors:
            # FixMe
            return None

        pwd = data.pop("password")
        data["credentials"] = [{"value": pwd, "type": "password"}]
        new_user = self.source.admin.create_user(data, exist_ok=False)
        return new_user


class Update(actions.Update):

    schema = JSONSchema({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "User update",
        "type": "object",
        "properties": {
            "email": {
                "type": "string",
                "description": "User email."
            }
        },
        "required": ["email"],
    })

    def update(self, uid: UserID, data: dict) -> bool:
        errors = list(self.schema.validate(data))
        if errors:
            # FixMe
            return None

        if kuid := self.source.admin.get_user_id(uid):
            self.admin.update_user(
                user_id=kuid,
                payload=data
            )
            return True
        return False


class Delete(actions.Delete):

    schema = None

    def delete(self, uid: UserID) -> bool:
        if kuid := self.source.admin.get_user_id(uid):
            self.source.admin.delete_user(user_id=kuid)
            return True
        return False
