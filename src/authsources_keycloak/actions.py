from authsources.abc import source, actions
from authsources.abc.protocols import RequestProtocol
from authsources.json import JSONSchema
from authsources_keycloak.source import KeycloakUser


class Fetch(actions.Getter):

    schema = None

    def get(self, request: RequestProtocol, uid: str) -> KeycloakUser | None:
        if kuid := self.source.admin.get_user_id(uid):
            data = self.source.admin.get_user(kuid)
            groups = self.source.admin.get_user_groups(kuid)
            data['groups'] = groups
            user = self.source.usertype(uid, data=data)
            return user


class Preflight(actions.Preflight):

    schema = None

    def preflight(self):
        env_token = self.request.app.config.keycloak.get(
            "header", "HTTP_ACCESS_TOKEN"
        )
        if token := self.request.environ.get(env_token):
            token_info = self.source.decode_token(token=token)
            user = self.source.usertype(
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
            yield self.source.usertype(user['username'], data=user)


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

    def challenge(self, credentials: dict) -> KeycloakUser | None:
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
        user = self.source.usertype(
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

    def update(self, uid: str, data: dict) -> bool:
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

    def delete(self, uid: str) -> bool:
        if kuid := self.source.admin.get_user_id(uid):
            self.source.admin.delete_user(user_id=kuid)
            return True
        return False


class Groups(actions.Groups):

    schema = None

    def list_groups(self):
        raise NotImplementedError('Not YET')

    @abc.abstractmethod
    def list_user_groups(self, userid: str):
        kuid = self.source.admin.get_user_id(userid)
        return self.source.admin.get_user_groups(user_id=kuid)


class Group(actions.Group):

    schema = None

    def list_group_users(self, groupid: str):
        group = self.source.admin.get_group_by_path(groupid)
        group_members = self.source.admin.get_group_members(group["id"])
        users = []
        for data in group_members:
            groups = self.user_groups(data['username'], kuid=data["id"])
            data['groups'] = groups
            yield self.source.factory(
                id=data["username"],
                metadata=None,
                data=data,
            )

    def add_group_user(self, groupid: str, userid: str):
            kuid = self.admin.get_user_id(userid)
        group = self.admin.get_group_by_path(groupid)
        self.admin.group_user_add(kuid, group["id"])



class ChangePassword(actions.ChangePassword):

    schema = None

    def change_password(self, uid: t.Any, new_value: str):
        if kuid := self.admin.get_user_id(uid):
            self.source.admin.set_user_password(
                user_id=kuid,
                password=new_value,
                temporary=True
            )
            return True
        return False
