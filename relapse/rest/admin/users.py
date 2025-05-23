# Copyright 2019 The Matrix.org Foundation C.I.C.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import hashlib
import hmac
import logging
import secrets
from http import HTTPStatus
from typing import TYPE_CHECKING, Optional

import attr

from relapse.api.constants import Direction, UserTypes
from relapse.api.errors import Codes, NotFoundError, RelapseError
from relapse.http.servlet import (
    RestServlet,
    assert_params_in_dict,
    parse_boolean,
    parse_enum,
    parse_integer,
    parse_json_object_from_request,
    parse_string,
    parse_strings_from_args,
)
from relapse.http.site import RelapseRequest
from relapse.rest.admin._base import (
    admin_patterns,
    assert_requester_is_admin,
    assert_user_is_admin,
)
from relapse.rest.client._base import client_patterns
from relapse.storage.databases.main.registration import ExternalIDReuseException
from relapse.storage.databases.main.stats import UserSortOrder
from relapse.types import JsonDict, JsonMapping, UserID

if TYPE_CHECKING:
    from relapse.server import HomeServer

logger = logging.getLogger(__name__)


class UsersRestServletV2(RestServlet):
    PATTERNS = admin_patterns("/users$", "v2")

    """Get request to list all local users.
    This needs user to have administrator access in Relapse.

    GET /_relapse/admin/v2/users?from=0&limit=10&guests=false

    returns:
        200 OK with list of users if success otherwise an error.

    The parameters `from` and `limit` are required only for pagination.
    By default, a `limit` of 100 is used.
    The parameter `user_id` can be used to filter by user id.
    The parameter `name` can be used to filter by user id or display name.
    The parameter `guests` can be used to exclude guest users.
    The parameter `deactivated` can be used to include deactivated users.
    The parameter `order_by` can be used to order the result.
    The parameter `not_user_type` can be used to exclude certain user types.
    The parameter `locked` can be used to include locked users.
    Possible values are `bot`, `support` or "empty string".
    "empty string" here means to exclude users without a type.
    """

    def __init__(self, hs: "HomeServer"):
        self.store = hs.get_datastores().main
        self.auth = hs.get_auth()
        self.admin_handler = hs.get_admin_handler()
        self._msc3866_enabled = hs.config.experimental.msc3866.enabled
        self._msc3861_enabled = hs.config.experimental.msc3861.enabled

    async def on_GET(self, request: RelapseRequest) -> tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        start = parse_integer(request, "from", default=0)
        limit = parse_integer(request, "limit", default=100)

        if start < 0:
            raise RelapseError(
                HTTPStatus.BAD_REQUEST,
                "Query parameter from must be a string representing a positive integer.",
                errcode=Codes.INVALID_PARAM,
            )

        if limit < 0:
            raise RelapseError(
                HTTPStatus.BAD_REQUEST,
                "Query parameter limit must be a string representing a positive integer.",
                errcode=Codes.INVALID_PARAM,
            )

        user_id = parse_string(request, "user_id")
        name = parse_string(request, "name")

        guests = parse_boolean(request, "guests", default=True)
        if self._msc3861_enabled and guests:
            raise RelapseError(
                HTTPStatus.BAD_REQUEST,
                "The guests parameter is not supported when MSC3861 is enabled.",
                errcode=Codes.INVALID_PARAM,
            )

        deactivated = parse_boolean(request, "deactivated", default=False)
        locked = parse_boolean(request, "locked", default=False)
        admins = parse_boolean(request, "admins")

        # If support for MSC3866 is not enabled, apply no filtering based on the
        # `approved` column.
        if self._msc3866_enabled:
            approved = parse_boolean(request, "approved", default=True)
        else:
            approved = True

        order_by = parse_string(
            request,
            "order_by",
            default=UserSortOrder.NAME.value,
            allowed_values=(
                UserSortOrder.NAME.value,
                UserSortOrder.DISPLAYNAME.value,
                UserSortOrder.GUEST.value,
                UserSortOrder.ADMIN.value,
                UserSortOrder.DEACTIVATED.value,
                UserSortOrder.USER_TYPE.value,
                UserSortOrder.AVATAR_URL.value,
                UserSortOrder.SHADOW_BANNED.value,
                UserSortOrder.CREATION_TS.value,
                UserSortOrder.LAST_SEEN_TS.value,
                UserSortOrder.LOCKED.value,
            ),
        )

        direction = parse_enum(request, "dir", Direction, default=Direction.FORWARDS)

        # twisted.web.server.Request.args is incorrectly defined as Optional[Any]
        args: dict[bytes, list[bytes]] = request.args  # type: ignore
        not_user_types = parse_strings_from_args(args, "not_user_type")

        users, total = await self.store.get_users_paginate(
            start,
            limit,
            user_id,
            name,
            guests,
            deactivated,
            admins,
            order_by,
            direction,
            approved,
            not_user_types,
            locked,
        )

        # If support for MSC3866 is not enabled, don't show the approval flag.
        filter = None
        if not self._msc3866_enabled:

            def _filter(a: attr.Attribute) -> bool:
                return a.name != "approved"

        ret = {"users": [attr.asdict(u, filter=filter) for u in users], "total": total}
        if (start + limit) < total:
            ret["next_token"] = str(start + len(users))

        return HTTPStatus.OK, ret


class UserRestServletV2(RestServlet):
    PATTERNS = admin_patterns("/users/(?P<user_id>[^/]*)$", "v2")

    """Get request to list user details.
    This needs user to have administrator access in Relapse.

    GET /_relapse/admin/v2/users/<user_id>

    returns:
        200 OK with user details if success otherwise an error.

    Put request to allow an administrator to add or modify a user.
    This needs user to have administrator access in Relapse.
    We use PUT instead of POST since we already know the id of the user
    object to create. POST could be used to create guests.

    PUT /_relapse/admin/v2/users/<user_id>
    {
        "password": "secret",
        "displayname": "User"
    }

    returns:
        201 OK with new user object if user was created or
        200 OK with modified user object if user was modified
        otherwise an error.
    """

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.auth = hs.get_auth()
        self.admin_handler = hs.get_admin_handler()
        self.store = hs.get_datastores().main
        self.auth_handler = hs.get_auth_handler()
        self.profile_handler = hs.get_profile_handler()
        self.set_password_handler = hs.get_set_password_handler()
        self.deactivate_account_handler = hs.get_deactivate_account_handler()
        self.registration_handler = hs.get_registration_handler()
        self.pusher_pool = hs.get_pusherpool()
        self._msc3866_enabled = hs.config.experimental.msc3866.enabled

    async def on_GET(
        self, request: RelapseRequest, user_id: str
    ) -> tuple[int, JsonMapping]:
        await assert_requester_is_admin(self.auth, request)

        target_user = UserID.from_string(user_id)
        if not self.hs.is_mine(target_user):
            raise RelapseError(HTTPStatus.BAD_REQUEST, "Can only look up local users")

        user_info_dict = await self.admin_handler.get_user(target_user)
        if not user_info_dict:
            raise NotFoundError("User not found")

        return HTTPStatus.OK, user_info_dict

    async def on_PUT(
        self, request: RelapseRequest, user_id: str
    ) -> tuple[int, JsonMapping]:
        requester = await self.auth.get_user_by_req(request)
        await assert_user_is_admin(self.auth, requester)

        target_user = UserID.from_string(user_id)
        body = parse_json_object_from_request(request)

        if not self.hs.is_mine(target_user):
            raise RelapseError(
                HTTPStatus.BAD_REQUEST,
                "This endpoint can only be used with local users",
            )

        user = await self.admin_handler.get_user(target_user)
        user_id = target_user.to_string()

        # check for required parameters for each threepid
        threepids = body.get("threepids")
        if threepids is not None:
            for threepid in threepids:
                assert_params_in_dict(threepid, ["medium", "address"])

        # check for required parameters for each external_id
        external_ids = body.get("external_ids")
        if external_ids is not None:
            for external_id in external_ids:
                assert_params_in_dict(external_id, ["auth_provider", "external_id"])

        user_type = body.get("user_type", None)
        if user_type is not None and user_type not in UserTypes.ALL_USER_TYPES:
            raise RelapseError(HTTPStatus.BAD_REQUEST, "Invalid user type")

        set_admin_to = body.get("admin", False)
        if not isinstance(set_admin_to, bool):
            raise RelapseError(
                HTTPStatus.BAD_REQUEST,
                "Param 'admin' must be a boolean, if given",
                Codes.BAD_JSON,
            )

        password = body.get("password", None)
        if password is not None:
            if not isinstance(password, str) or len(password) > 512:
                raise RelapseError(HTTPStatus.BAD_REQUEST, "Invalid password")

        logout_devices = body.get("logout_devices", True)
        if not isinstance(logout_devices, bool):
            raise RelapseError(
                HTTPStatus.BAD_REQUEST,
                "'logout_devices' parameter is not of type boolean",
            )

        deactivate = body.get("deactivated", False)
        if not isinstance(deactivate, bool):
            raise RelapseError(
                HTTPStatus.BAD_REQUEST, "'deactivated' parameter is not of type boolean"
            )

        lock = body.get("locked", False)
        if not isinstance(lock, bool):
            raise RelapseError(
                HTTPStatus.BAD_REQUEST, "'locked' parameter is not of type boolean"
            )

        if deactivate and lock:
            raise RelapseError(
                HTTPStatus.BAD_REQUEST, "An user can't be deactivated and locked"
            )

        approved: Optional[bool] = None
        if "approved" in body and self._msc3866_enabled:
            approved = body["approved"]
            if not isinstance(approved, bool):
                raise RelapseError(
                    HTTPStatus.BAD_REQUEST,
                    "'approved' parameter is not of type boolean",
                )

        # convert List[Dict[str, str]] into List[Tuple[str, str]]
        if external_ids is not None:
            new_external_ids = [
                (external_id["auth_provider"], external_id["external_id"])
                for external_id in external_ids
            ]

        # convert List[Dict[str, str]] into Set[Tuple[str, str]]
        if threepids is not None:
            new_threepids = {
                (threepid["medium"], threepid["address"]) for threepid in threepids
            }

        if user:  # modify user
            if "displayname" in body:
                await self.profile_handler.set_displayname(
                    target_user, requester, body["displayname"], True
                )

            if threepids is not None:
                # get changed threepids (added and removed)
                cur_threepids = {
                    (threepid.medium, threepid.address)
                    for threepid in await self.store.user_get_threepids(user_id)
                }
                add_threepids = new_threepids - cur_threepids
                del_threepids = cur_threepids - new_threepids

                # remove old threepids
                for medium, address in del_threepids:
                    try:
                        # Attempt to remove any known bindings of this third-party ID
                        # and user ID from identity servers.
                        await self.hs.get_identity_handler().try_unbind_threepid(
                            user_id, medium, address, id_server=None
                        )
                    except Exception:
                        logger.exception("Failed to remove threepids")
                        raise RelapseError(500, "Failed to remove threepids")

                    # Delete the local association of this user ID and third-party ID.
                    await self.auth_handler.delete_local_threepid(
                        user_id, medium, address
                    )

                # add new threepids
                current_time = self.hs.get_clock().time_msec()
                for medium, address in add_threepids:
                    await self.auth_handler.add_threepid(
                        user_id, medium, address, current_time
                    )

            if external_ids is not None:
                try:
                    await self.store.replace_user_external_id(
                        new_external_ids,
                        user_id,
                    )
                except ExternalIDReuseException:
                    raise RelapseError(
                        HTTPStatus.CONFLICT, "External id is already in use."
                    )

            if "avatar_url" in body:
                await self.profile_handler.set_avatar_url(
                    target_user, requester, body["avatar_url"], True
                )

            if "admin" in body:
                if set_admin_to != user["admin"]:
                    auth_user = requester.user
                    if target_user == auth_user and not set_admin_to:
                        raise RelapseError(
                            HTTPStatus.BAD_REQUEST, "You may not demote yourself."
                        )

                    await self.store.set_server_admin(target_user, set_admin_to)

            if password is not None:
                new_password_hash = await self.auth_handler.hash(password)

                await self.set_password_handler.set_password(
                    target_user.to_string(),
                    new_password_hash,
                    logout_devices,
                    requester,
                )

            if "deactivated" in body:
                if deactivate and not user["deactivated"]:
                    await self.deactivate_account_handler.deactivate_account(
                        target_user.to_string(), False, requester, by_admin=True
                    )
                elif not deactivate and user["deactivated"]:
                    if (
                        "password" not in body
                        and self.auth_handler.can_change_password()
                    ):
                        raise RelapseError(
                            HTTPStatus.BAD_REQUEST,
                            "Must provide a password to re-activate an account.",
                        )

                    await self.deactivate_account_handler.activate_account(
                        target_user.to_string()
                    )

            if "locked" in body:
                if lock and not user["locked"]:
                    await self.store.set_user_locked_status(user_id, True)
                elif not lock and user["locked"]:
                    await self.store.set_user_locked_status(user_id, False)

            if "user_type" in body:
                await self.store.set_user_type(target_user, user_type)

            if approved is not None:
                await self.store.update_user_approval_status(target_user, approved)

            user = await self.admin_handler.get_user(target_user)
            assert user is not None

            return HTTPStatus.OK, user

        else:  # create user
            displayname = body.get("displayname", None)

            password_hash = None
            if password is not None:
                password_hash = await self.auth_handler.hash(password)

            new_user_approved = True
            if self._msc3866_enabled and approved is not None:
                new_user_approved = approved

            user_id = await self.registration_handler.register_user(
                localpart=target_user.localpart,
                password_hash=password_hash,
                admin=set_admin_to,
                default_display_name=displayname,
                user_type=user_type,
                by_admin=True,
                approved=new_user_approved,
            )

            if threepids is not None:
                current_time = self.hs.get_clock().time_msec()
                for medium, address in new_threepids:
                    await self.auth_handler.add_threepid(
                        user_id, medium, address, current_time
                    )
                    if (
                        self.hs.config.email.email_enable_notifs
                        and self.hs.config.email.email_notif_for_new_users
                        and medium == "email"
                    ):
                        await self.pusher_pool.add_or_update_pusher(
                            user_id=user_id,
                            kind="email",
                            app_id="m.email",
                            app_display_name="Email Notifications",
                            device_display_name=address,
                            pushkey=address,
                            lang=None,
                            data={},
                        )

            if external_ids is not None:
                try:
                    for auth_provider, external_id in new_external_ids:
                        await self.store.record_user_external_id(
                            auth_provider,
                            external_id,
                            user_id,
                        )
                except ExternalIDReuseException:
                    raise RelapseError(
                        HTTPStatus.CONFLICT, "External id is already in use."
                    )

            if "avatar_url" in body and isinstance(body["avatar_url"], str):
                await self.profile_handler.set_avatar_url(
                    target_user, requester, body["avatar_url"], True
                )

            user_info_dict = await self.admin_handler.get_user(target_user)
            assert user_info_dict is not None

            return HTTPStatus.CREATED, user_info_dict


class UserRegisterServlet(RestServlet):
    """
    Attributes:
         NONCE_TIMEOUT (int): Seconds until a generated nonce won't be accepted
         nonces (dict[str, int]): The nonces that we will accept. A dict of
             nonce to the time it was generated, in int seconds.
    """

    PATTERNS = admin_patterns("/register$")
    NONCE_TIMEOUT = 60

    def __init__(self, hs: "HomeServer"):
        self.auth_handler = hs.get_auth_handler()
        self.reactor = hs.get_reactor()
        self.nonces: dict[str, int] = {}
        self.hs = hs

    def _clear_old_nonces(self) -> None:
        """
        Clear out old nonces that are older than NONCE_TIMEOUT.
        """
        now = int(self.reactor.seconds())

        for k, v in list(self.nonces.items()):
            if now - v > self.NONCE_TIMEOUT:
                del self.nonces[k]

    def on_GET(self, request: RelapseRequest) -> tuple[int, JsonDict]:
        """
        Generate a new nonce.
        """
        self._clear_old_nonces()

        nonce = secrets.token_hex(64)
        self.nonces[nonce] = int(self.reactor.seconds())
        return HTTPStatus.OK, {"nonce": nonce}

    async def on_POST(self, request: RelapseRequest) -> tuple[int, JsonDict]:
        self._clear_old_nonces()

        if not self.hs.config.registration.registration_shared_secret:
            raise RelapseError(
                HTTPStatus.BAD_REQUEST, "Shared secret registration is not enabled"
            )

        body = parse_json_object_from_request(request)

        if "nonce" not in body:
            raise RelapseError(
                HTTPStatus.BAD_REQUEST,
                "nonce must be specified",
                errcode=Codes.BAD_JSON,
            )

        nonce = body["nonce"]

        if nonce not in self.nonces:
            raise RelapseError(HTTPStatus.BAD_REQUEST, "unrecognised nonce")

        # Delete the nonce, so it can't be reused, even if it's invalid
        del self.nonces[nonce]

        if "username" not in body:
            raise RelapseError(
                HTTPStatus.BAD_REQUEST,
                "username must be specified",
                errcode=Codes.BAD_JSON,
            )
        else:
            if not isinstance(body["username"], str) or len(body["username"]) > 512:
                raise RelapseError(HTTPStatus.BAD_REQUEST, "Invalid username")

            username = body["username"].encode("utf-8")
            if b"\x00" in username:
                raise RelapseError(HTTPStatus.BAD_REQUEST, "Invalid username")

        if "password" not in body:
            raise RelapseError(
                HTTPStatus.BAD_REQUEST,
                "password must be specified",
                errcode=Codes.BAD_JSON,
            )
        else:
            password = body["password"]
            if not isinstance(password, str) or len(password) > 512:
                raise RelapseError(HTTPStatus.BAD_REQUEST, "Invalid password")

            password_bytes = password.encode("utf-8")
            if b"\x00" in password_bytes:
                raise RelapseError(HTTPStatus.BAD_REQUEST, "Invalid password")

            password_hash = await self.auth_handler.hash(password)

        admin = body.get("admin", None)
        user_type = body.get("user_type", None)
        displayname = body.get("displayname", None)

        if user_type is not None and user_type not in UserTypes.ALL_USER_TYPES:
            raise RelapseError(HTTPStatus.BAD_REQUEST, "Invalid user type")

        if "mac" not in body:
            raise RelapseError(
                HTTPStatus.BAD_REQUEST, "mac must be specified", errcode=Codes.BAD_JSON
            )

        got_mac = body["mac"]

        want_mac_builder = hmac.new(
            key=self.hs.config.registration.registration_shared_secret.encode(),
            digestmod=hashlib.sha1,
        )
        want_mac_builder.update(nonce.encode("utf8"))
        want_mac_builder.update(b"\x00")
        want_mac_builder.update(username)
        want_mac_builder.update(b"\x00")
        want_mac_builder.update(password_bytes)
        want_mac_builder.update(b"\x00")
        want_mac_builder.update(b"admin" if admin else b"notadmin")
        if user_type:
            want_mac_builder.update(b"\x00")
            want_mac_builder.update(user_type.encode("utf8"))

        want_mac = want_mac_builder.hexdigest()

        if not hmac.compare_digest(want_mac.encode("ascii"), got_mac.encode("ascii")):
            raise RelapseError(HTTPStatus.FORBIDDEN, "HMAC incorrect")

        should_issue_refresh_token = body.get("refresh_token", False)
        if not isinstance(should_issue_refresh_token, bool):
            raise RelapseError(
                HTTPStatus.BAD_REQUEST, "refresh_token must be a boolean"
            )

        # Reuse the parts of RegisterRestServlet to reduce code duplication
        from relapse.rest.client.register import RegisterRestServlet

        register = RegisterRestServlet(self.hs)

        user_id = await register.registration_handler.register_user(
            localpart=body["username"].lower(),
            password_hash=password_hash,
            admin=bool(admin),
            user_type=user_type,
            default_display_name=displayname,
            by_admin=True,
            approved=True,
        )

        result = await register._create_registration_details(
            user_id, body, should_issue_refresh_token=should_issue_refresh_token
        )
        return HTTPStatus.OK, result


class WhoisRestServlet(RestServlet):
    path_regex = "/whois/(?P<user_id>[^/]*)$"
    PATTERNS = [
        *admin_patterns(path_regex),
        # URL for spec reason
        # https://matrix.org/docs/spec/client_server/r0.6.1#get-matrix-client-r0-admin-whois-userid
        *client_patterns("/admin" + path_regex, v1=True),
    ]

    def __init__(self, hs: "HomeServer"):
        self.auth = hs.get_auth()
        self.admin_handler = hs.get_admin_handler()
        self.is_mine = hs.is_mine

    async def on_GET(
        self, request: RelapseRequest, user_id: str
    ) -> tuple[int, JsonMapping]:
        target_user = UserID.from_string(user_id)
        requester = await self.auth.get_user_by_req(request)

        if target_user != requester.user:
            await assert_user_is_admin(self.auth, requester)

        if not self.is_mine(target_user):
            raise RelapseError(HTTPStatus.BAD_REQUEST, "Can only whois a local user")

        ret = await self.admin_handler.get_whois(target_user)

        return HTTPStatus.OK, ret


class DeactivateAccountRestServlet(RestServlet):
    PATTERNS = admin_patterns("/deactivate/(?P<target_user_id>[^/]*)$")

    def __init__(self, hs: "HomeServer"):
        self._deactivate_account_handler = hs.get_deactivate_account_handler()
        self.auth = hs.get_auth()
        self.is_mine = hs.is_mine
        self.store = hs.get_datastores().main

    async def on_POST(
        self, request: RelapseRequest, target_user_id: str
    ) -> tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        await assert_user_is_admin(self.auth, requester)

        if not self.is_mine(UserID.from_string(target_user_id)):
            raise RelapseError(
                HTTPStatus.BAD_REQUEST, "Can only deactivate local users"
            )

        if not await self.store.get_user_by_id(target_user_id):
            raise NotFoundError("User not found")

        body = parse_json_object_from_request(request, allow_empty_body=True)
        erase = body.get("erase", False)
        if not isinstance(erase, bool):
            raise RelapseError(
                HTTPStatus.BAD_REQUEST,
                "Param 'erase' must be a boolean, if given",
                Codes.BAD_JSON,
            )

        result = await self._deactivate_account_handler.deactivate_account(
            target_user_id, erase, requester, by_admin=True
        )
        if result:
            id_server_unbind_result = "success"
        else:
            id_server_unbind_result = "no-support"

        return HTTPStatus.OK, {"id_server_unbind_result": id_server_unbind_result}


class AccountValidityRenewServlet(RestServlet):
    PATTERNS = admin_patterns("/account_validity/validity$")

    def __init__(self, hs: "HomeServer"):
        self.account_validity_handler = hs.get_account_validity_handler()
        self.account_validity_module_callbacks = (
            hs.get_module_api_callbacks().account_validity
        )
        self.auth = hs.get_auth()

    async def on_POST(self, request: RelapseRequest) -> tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        if self.account_validity_module_callbacks.on_legacy_admin_request_callback:
            expiration_ts = await self.account_validity_module_callbacks.on_legacy_admin_request_callback(
                request
            )
        else:
            body = parse_json_object_from_request(request)

            if "user_id" not in body:
                raise RelapseError(
                    HTTPStatus.BAD_REQUEST,
                    "Missing property 'user_id' in the request body",
                )

            expiration_ts = await self.account_validity_handler.renew_account_for_user(
                body["user_id"],
                body.get("expiration_ts"),
                not body.get("enable_renewal_emails", True),
            )

        res = {"expiration_ts": expiration_ts}
        return HTTPStatus.OK, res


class ResetPasswordRestServlet(RestServlet):
    """Post request to allow an administrator reset password for a user.
    This needs user to have administrator access in Relapse.
        Example:
            http://localhost:8008/_relapse/admin/v1/reset_password/
            @user:to_reset_password?access_token=admin_access_token
        JsonBodyToSend:
            {
                "new_password": "secret"
            }
        Returns:
            200 OK with empty object if success otherwise an error.
    """

    PATTERNS = admin_patterns("/reset_password/(?P<target_user_id>[^/]*)$")

    def __init__(self, hs: "HomeServer"):
        self.store = hs.get_datastores().main
        self.auth = hs.get_auth()
        self.auth_handler = hs.get_auth_handler()
        self._set_password_handler = hs.get_set_password_handler()

    async def on_POST(
        self, request: RelapseRequest, target_user_id: str
    ) -> tuple[int, JsonDict]:
        """Post request to allow an administrator reset password for a user.
        This needs user to have administrator access in Relapse.
        """
        requester = await self.auth.get_user_by_req(request)
        await assert_user_is_admin(self.auth, requester)

        UserID.from_string(target_user_id)

        params = parse_json_object_from_request(request)
        assert_params_in_dict(params, ["new_password"])
        new_password = params["new_password"]
        logout_devices = params.get("logout_devices", True)

        new_password_hash = await self.auth_handler.hash(new_password)

        await self._set_password_handler.set_password(
            target_user_id, new_password_hash, logout_devices, requester
        )
        return HTTPStatus.OK, {}


class SearchUsersRestServlet(RestServlet):
    """Get request to search user table for specific users according to
    search term.
    This needs user to have administrator access in Relapse.
        Example:
            http://localhost:8008/_relapse/admin/v1/search_users/
            @admin:user?access_token=admin_access_token&term=alice
        Returns:
            200 OK with json object {list[dict[str, Any]], count} or empty object.
    """

    PATTERNS = admin_patterns("/search_users/(?P<target_user_id>[^/]*)$")

    def __init__(self, hs: "HomeServer"):
        self.store = hs.get_datastores().main
        self.auth = hs.get_auth()
        self.is_mine = hs.is_mine

    async def on_GET(
        self, request: RelapseRequest, target_user_id: str
    ) -> tuple[int, Optional[list[JsonDict]]]:
        """Get request to search user table for specific users according to
        search term.
        This needs user to have a administrator access in Relapse.
        """
        await assert_requester_is_admin(self.auth, request)

        target_user = UserID.from_string(target_user_id)

        # To allow all users to get the users list
        # if not is_admin and target_user != auth_user:
        #     raise AuthError(HTTPStatus.FORBIDDEN, "You are not a server admin")

        if not self.is_mine(target_user):
            raise RelapseError(HTTPStatus.BAD_REQUEST, "Can only users a local user")

        term = parse_string(request, "term", required=True)
        logger.info("term: %s ", term)

        ret = await self.store.search_users(term)
        results = [
            {
                "name": name,
                "password_hash": password_hash,
                "is_guest": bool(is_guest),
                "admin": bool(admin),
                "user_type": user_type,
            }
            for name, password_hash, is_guest, admin, user_type in ret
        ]

        return HTTPStatus.OK, results


class UserAdminServlet(RestServlet):
    """
    Get or set whether or not a user is a server administrator.

    Note that only local users can be server administrators, and that an
    administrator may not demote themselves.

    Only server administrators can use this API.

    Examples:
        * Get
            GET /_relapse/admin/v1/users/@nonadmin:example.com/admin
            response on success:
                {
                    "admin": false
                }
        * Set
            PUT /_relapse/admin/v1/users/@reivilibre:librepush.net/admin
            request body:
                {
                    "admin": true
                }
            response on success:
                {}
    """

    PATTERNS = admin_patterns("/users/(?P<user_id>[^/]*)/admin$")

    def __init__(self, hs: "HomeServer"):
        self.store = hs.get_datastores().main
        self.auth = hs.get_auth()
        self.is_mine = hs.is_mine

    async def on_GET(
        self, request: RelapseRequest, user_id: str
    ) -> tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        target_user = UserID.from_string(user_id)

        if not self.is_mine(target_user):
            raise RelapseError(
                HTTPStatus.BAD_REQUEST,
                "Only local users can be admins of this homeserver",
            )

        is_admin = await self.store.is_server_admin(target_user)

        return HTTPStatus.OK, {"admin": is_admin}

    async def on_PUT(
        self, request: RelapseRequest, user_id: str
    ) -> tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        await assert_user_is_admin(self.auth, requester)
        auth_user = requester.user

        target_user = UserID.from_string(user_id)

        body = parse_json_object_from_request(request)

        assert_params_in_dict(body, ["admin"])

        if not self.is_mine(target_user):
            raise RelapseError(
                HTTPStatus.BAD_REQUEST,
                "Only local users can be admins of this homeserver",
            )

        set_admin_to = bool(body["admin"])

        if target_user == auth_user and not set_admin_to:
            raise RelapseError(HTTPStatus.BAD_REQUEST, "You may not demote yourself.")

        await self.store.set_server_admin(target_user, set_admin_to)

        return HTTPStatus.OK, {}


class UserMembershipRestServlet(RestServlet):
    """
    Get room list of an user.
    """

    PATTERNS = admin_patterns("/users/(?P<user_id>[^/]*)/joined_rooms$")

    def __init__(self, hs: "HomeServer"):
        self.is_mine = hs.is_mine
        self.auth = hs.get_auth()
        self.store = hs.get_datastores().main

    async def on_GET(
        self, request: RelapseRequest, user_id: str
    ) -> tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        room_ids = await self.store.get_rooms_for_user(user_id)
        ret = {"joined_rooms": list(room_ids), "total": len(room_ids)}
        return HTTPStatus.OK, ret


class PushersRestServlet(RestServlet):
    """
    Gets information about all pushers for a specific `user_id`.

    Example:
        http://localhost:8008/_relapse/admin/v1/users/
        @user:server/pushers

    Returns:
        A dictionary with keys:
            pushers: Dictionary containing pushers information.
            total: Number of pushers in dictionary `pushers`.
    """

    PATTERNS = admin_patterns("/users/(?P<user_id>[^/]*)/pushers$")

    def __init__(self, hs: "HomeServer"):
        self.is_mine = hs.is_mine
        self.store = hs.get_datastores().main
        self.auth = hs.get_auth()

    async def on_GET(
        self, request: RelapseRequest, user_id: str
    ) -> tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        if not self.is_mine(UserID.from_string(user_id)):
            raise RelapseError(HTTPStatus.BAD_REQUEST, "Can only look up local users")

        if not await self.store.get_user_by_id(user_id):
            raise NotFoundError("User not found")

        pushers = await self.store.get_pushers_by_user_id(user_id)

        filtered_pushers = [p.as_dict() for p in pushers]

        return HTTPStatus.OK, {
            "pushers": filtered_pushers,
            "total": len(filtered_pushers),
        }


class UserTokenRestServlet(RestServlet):
    """An admin API for logging in as a user.

    Example:

        POST /_relapse/admin/v1/users/@test:example.com/login
        {}

        200 OK
        {
            "access_token": "<some_token>"
        }
    """

    PATTERNS = admin_patterns("/users/(?P<user_id>[^/]*)/login$")

    def __init__(self, hs: "HomeServer"):
        self.store = hs.get_datastores().main
        self.auth = hs.get_auth()
        self.auth_handler = hs.get_auth_handler()
        self.is_mine_id = hs.is_mine_id

    async def on_POST(
        self, request: RelapseRequest, user_id: str
    ) -> tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        await assert_user_is_admin(self.auth, requester)
        auth_user = requester.user

        if not self.is_mine_id(user_id):
            raise RelapseError(
                HTTPStatus.BAD_REQUEST, "Only local users can be logged in as"
            )

        body = parse_json_object_from_request(request, allow_empty_body=True)

        valid_until_ms = body.get("valid_until_ms")
        if type(valid_until_ms) not in (int, type(None)):
            raise RelapseError(
                HTTPStatus.BAD_REQUEST, "'valid_until_ms' parameter must be an int"
            )

        if auth_user.to_string() == user_id:
            raise RelapseError(
                HTTPStatus.BAD_REQUEST, "Cannot use admin API to login as self"
            )

        token = await self.auth_handler.create_access_token_for_user_id(
            user_id=auth_user.to_string(),
            device_id=None,
            valid_until_ms=valid_until_ms,
            puppets_user_id=user_id,
        )

        return HTTPStatus.OK, {"access_token": token}


class ShadowBanRestServlet(RestServlet):
    """An admin API for controlling whether a user is shadow-banned.

    A shadow-banned users receives successful responses to their client-server
    API requests, but the events are not propagated into rooms.

    Shadow-banning a user should be used as a tool of last resort and may lead
    to confusing or broken behaviour for the client.

    Example of shadow-banning a user:

        POST /_relapse/admin/v1/users/@test:example.com/shadow_ban
        {}

        200 OK
        {}

    Example of removing a user from being shadow-banned:

        DELETE /_relapse/admin/v1/users/@test:example.com/shadow_ban
        {}

        200 OK
        {}
    """

    PATTERNS = admin_patterns("/users/(?P<user_id>[^/]*)/shadow_ban$")

    def __init__(self, hs: "HomeServer"):
        self.store = hs.get_datastores().main
        self.auth = hs.get_auth()
        self.is_mine_id = hs.is_mine_id

    async def on_POST(
        self, request: RelapseRequest, user_id: str
    ) -> tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        if not self.is_mine_id(user_id):
            raise RelapseError(
                HTTPStatus.BAD_REQUEST, "Only local users can be shadow-banned"
            )

        await self.store.set_shadow_banned(UserID.from_string(user_id), True)

        return HTTPStatus.OK, {}

    async def on_DELETE(
        self, request: RelapseRequest, user_id: str
    ) -> tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        if not self.is_mine_id(user_id):
            raise RelapseError(
                HTTPStatus.BAD_REQUEST, "Only local users can be shadow-banned"
            )

        await self.store.set_shadow_banned(UserID.from_string(user_id), False)

        return HTTPStatus.OK, {}


class RateLimitRestServlet(RestServlet):
    """An admin API to override ratelimiting for an user.

    Example:
        POST /_relapse/admin/v1/users/@test:example.com/override_ratelimit
        {
          "messages_per_second": 0,
          "burst_count": 0
        }
        200 OK
        {
          "messages_per_second": 0,
          "burst_count": 0
        }
    """

    PATTERNS = admin_patterns("/users/(?P<user_id>[^/]*)/override_ratelimit$")

    def __init__(self, hs: "HomeServer"):
        self.store = hs.get_datastores().main
        self.auth = hs.get_auth()
        self.is_mine_id = hs.is_mine_id

    async def on_GET(
        self, request: RelapseRequest, user_id: str
    ) -> tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        if not self.is_mine_id(user_id):
            raise RelapseError(HTTPStatus.BAD_REQUEST, "Can only look up local users")

        if not await self.store.get_user_by_id(user_id):
            raise NotFoundError("User not found")

        ratelimit = await self.store.get_ratelimit_for_user(user_id)

        if ratelimit:
            # convert `null` to `0` for consistency
            # both values do the same in retelimit handler
            ret = {
                "messages_per_second": 0
                if ratelimit.messages_per_second is None
                else ratelimit.messages_per_second,
                "burst_count": 0
                if ratelimit.burst_count is None
                else ratelimit.burst_count,
            }
        else:
            ret = {}

        return HTTPStatus.OK, ret

    async def on_POST(
        self, request: RelapseRequest, user_id: str
    ) -> tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        if not self.is_mine_id(user_id):
            raise RelapseError(
                HTTPStatus.BAD_REQUEST, "Only local users can be ratelimited"
            )

        if not await self.store.get_user_by_id(user_id):
            raise NotFoundError("User not found")

        body = parse_json_object_from_request(request, allow_empty_body=True)

        messages_per_second = body.get("messages_per_second", 0)
        burst_count = body.get("burst_count", 0)

        if (
            type(messages_per_second) is not int  # noqa: E721
            or messages_per_second < 0
        ):
            raise RelapseError(
                HTTPStatus.BAD_REQUEST,
                "%r parameter must be a positive int" % (messages_per_second,),
                errcode=Codes.INVALID_PARAM,
            )

        if type(burst_count) is not int or burst_count < 0:  # noqa: E721
            raise RelapseError(
                HTTPStatus.BAD_REQUEST,
                "%r parameter must be a positive int" % (burst_count,),
                errcode=Codes.INVALID_PARAM,
            )

        await self.store.set_ratelimit_for_user(
            user_id, messages_per_second, burst_count
        )
        ratelimit = await self.store.get_ratelimit_for_user(user_id)
        assert ratelimit is not None

        ret = {
            "messages_per_second": ratelimit.messages_per_second,
            "burst_count": ratelimit.burst_count,
        }

        return HTTPStatus.OK, ret

    async def on_DELETE(
        self, request: RelapseRequest, user_id: str
    ) -> tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        if not self.is_mine_id(user_id):
            raise RelapseError(
                HTTPStatus.BAD_REQUEST, "Only local users can be ratelimited"
            )

        if not await self.store.get_user_by_id(user_id):
            raise NotFoundError("User not found")

        await self.store.delete_ratelimit_for_user(user_id)

        return HTTPStatus.OK, {}


class AccountDataRestServlet(RestServlet):
    """Retrieve the given user's account data"""

    PATTERNS = admin_patterns("/users/(?P<user_id>[^/]*)/accountdata")

    def __init__(self, hs: "HomeServer"):
        self._auth = hs.get_auth()
        self._store = hs.get_datastores().main
        self._is_mine_id = hs.is_mine_id

    async def on_GET(
        self, request: RelapseRequest, user_id: str
    ) -> tuple[int, JsonDict]:
        await assert_requester_is_admin(self._auth, request)

        if not self._is_mine_id(user_id):
            raise RelapseError(HTTPStatus.BAD_REQUEST, "Can only look up local users")

        if not await self._store.get_user_by_id(user_id):
            raise NotFoundError("User not found")

        global_data = await self._store.get_global_account_data_for_user(user_id)
        by_room_data = await self._store.get_room_account_data_for_user(user_id)
        return HTTPStatus.OK, {
            "account_data": {
                "global": global_data,
                "rooms": by_room_data,
            },
        }


class UserReplaceMasterCrossSigningKeyRestServlet(RestServlet):
    """Allow a given user to replace their master cross-signing key without UIA.

    This replacement is permitted for a limited period (currently 10 minutes).

    While this is exposed via the admin API, this is intended for use by the
    Matrix Authentication Service rather than server admins.
    """

    PATTERNS = admin_patterns(
        "/users/(?P<user_id>[^/]*)/_allow_cross_signing_replacement_without_uia"
    )
    REPLACEMENT_PERIOD_MS = 10 * 60 * 1000  # 10 minutes

    def __init__(self, hs: "HomeServer"):
        self._auth = hs.get_auth()
        self._store = hs.get_datastores().main

    async def on_POST(
        self,
        request: RelapseRequest,
        user_id: str,
    ) -> tuple[int, JsonDict]:
        await assert_requester_is_admin(self._auth, request)

        if user_id is None:
            raise NotFoundError("User not found")

        timestamp = (
            await self._store.allow_master_cross_signing_key_replacement_without_uia(
                user_id, self.REPLACEMENT_PERIOD_MS
            )
        )

        if timestamp is None:
            raise NotFoundError("User has no master cross-signing key")

        return HTTPStatus.OK, {"updatable_without_uia_before_ms": timestamp}


class UserByExternalId(RestServlet):
    """Find a user based on an external ID from an auth provider"""

    PATTERNS = admin_patterns(
        "/auth_providers/(?P<provider>[^/]*)/users/(?P<external_id>[^/]*)"
    )

    def __init__(self, hs: "HomeServer"):
        self._auth = hs.get_auth()
        self._store = hs.get_datastores().main

    async def on_GET(
        self,
        request: RelapseRequest,
        provider: str,
        external_id: str,
    ) -> tuple[int, JsonDict]:
        await assert_requester_is_admin(self._auth, request)

        user_id = await self._store.get_user_by_external_id(provider, external_id)

        if user_id is None:
            raise NotFoundError("User not found")

        return HTTPStatus.OK, {"user_id": user_id}


class UserByThreePid(RestServlet):
    """Find a user based on 3PID of a particular medium"""

    PATTERNS = admin_patterns("/threepid/(?P<medium>[^/]*)/users/(?P<address>[^/]*)")

    def __init__(self, hs: "HomeServer"):
        self._auth = hs.get_auth()
        self._store = hs.get_datastores().main

    async def on_GET(
        self,
        request: RelapseRequest,
        medium: str,
        address: str,
    ) -> tuple[int, JsonDict]:
        await assert_requester_is_admin(self._auth, request)

        user_id = await self._store.get_user_id_by_threepid(medium, address)

        if user_id is None:
            raise NotFoundError("User not found")

        return HTTPStatus.OK, {"user_id": user_id}
