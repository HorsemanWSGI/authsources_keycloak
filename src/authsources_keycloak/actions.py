import typing as t
from authsources import source, protocols
from authsources.json import JSONSchema
from authsources_keycloak.source import KeycloakUser


class Fetch(source.SourceAction):
    __protocols__ = (protocols.Getter,)

    schema = None

    def get(self, uid: str) -> KeycloakUser | None:
        if kuid := self.source.admin.get_user_id(uid):
            data = self.source.admin.get_user(kuid)
            groups = self.source.admin.get_user_groups(kuid)
            data['groups'] = groups
            user = self.source.usertype(uid, data=data)
            return user


class Preflight(source.SourceAction):
    __protocols__ = (protocols.Preflight,)

    schema = None

    def preflight(self, request: protocols.RequestProtocol):
        env_token = self.source.config.get("header", "HTTP_ACCESS_TOKEN")
        if token := request.environ.get(env_token):
            token_info = self.source.decode_token(token=token)
            user = self.source.usertype(
                token_info['preferred_username'],
                data=token_info
            )
            return user


class Search(source.SourceAction):

    __protocols__ = (protocols.Search,)

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
        results = self.source.admin.get_users(
            query={"max": limit, "first": index, **criterions}
        )
        for user in results:
            yield self.source.usertype(user['username'], data=user)


class Challenge(source.SourceAction):

    __protocols__ = (protocols.Challenge,)

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


class Create(source.SourceAction):

    __protocols__ = (protocols.Create,)

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

    def create(self, data: dict) -> bool:
        self.schema.validate(data)
        pwd = data.pop("password")
        data["credentials"] = [{"value": pwd, "type": "password"}]
        new_user = self.source.admin.create_user(data, exist_ok=False)
        return True


class Update(source.SourceAction):

    __protocols__ = (protocols.Update,)

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
            self.source.admin.update_user(
                user_id=kuid,
                payload=data
            )
            return True
        return False


class Delete(source.SourceAction):

    __protocols__ = (protocols.Delete,)

    schema = None

    def delete(self, uid: str) -> bool:
        if kuid := self.source.admin.get_user_id(uid):
            self.source.admin.delete_user(user_id=kuid)
            return True
        return False


class Groups(source.SourceAction):

    __protocols__ = (protocols.Groups,)

    schema = None

    def list_groups(self):
        groups = self.source.admin.get_groups()
        return groups

    def list_user_groups(self, userid: str):
        kuid = self.source.admin.get_user_id(userid)
        return self.source.admin.get_user_groups(user_id=kuid)


class GroupCreate(source.SourceAction):

    __protocols__ = (protocols.GroupCreate,)

    schema = JSONSchema({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "GroupRepresentation",
        "type": "object",
        "properties": {
            "id" : {
                "type" : "string"
            },
            "name" : {
                "type" : "string"
            },
            "path" : {
                "type" : "string"
            }
        },
        "required": ["name"],
    })

    def create_group(self, data: dict, *, parent: str | None = None) -> bool:
        self.schema.validate(data)
        self.source.admin.create_group(data)
        return True


class GroupDelete(source.SourceAction):

    __protocols__ = (protocols.GroupDelete,)

    def delete_group(self, groupid: str) -> bool:
        group = self.source.admin.get_group_by_path(groupid)
        self.source.admin.delete_group(group['id'])
        return True


class GroupManage(source.SourceAction):

    __protocols__ = (protocols.GroupManage,)

    schema = None

    def list_group_users(self, groupid: str):
        group = self.source.admin.get_group_by_path(groupid)
        group_members = self.source.admin.get_group_members(group["id"])
        users = []
        for data in group_members:
            yield self.source.usertype(
                id=data["username"],
                data=data,
            )

    def add_group_user(self, groupid: str, userid: str) -> bool:
        kuid = self.source.admin.get_user_id(userid)
        group = self.source.admin.get_group_by_path(groupid)
        self.source.admin.group_user_add(kuid, group["id"])
        return True

    def remove_group_user(self, groupid: str, userid: str):
        kuid = self.source.admin.get_user_id(userid)
        group = self.source.admin.get_group_by_path(groupid)
        self.source.admin.group_user_remove(kuid, group["id"])
        return True


class ChangePassword(source.SourceAction):

    __protocols__ = (protocols.ChangePassword,)

    schema = None

    def change_password(self, uid: t.Any, new_value: str):
        if kuid := self.source.admin.get_user_id(uid):
            self.source.admin.set_user_password(
                user_id=kuid,
                password=new_value,
                temporary=True
            )
            return True
        return False
