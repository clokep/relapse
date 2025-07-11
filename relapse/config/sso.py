# Copyright 2020-2021 The Matrix.org Foundation C.I.C.
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
from typing import Any, Optional

import attr

from relapse.types import JsonDict

from ._base import Config


@attr.s(frozen=True, auto_attribs=True)
class SsoAttributeRequirement:
    """Object describing a single requirement for SSO attributes."""

    attribute: str
    # If a value is not given, than the attribute must simply exist.
    value: Optional[str]

    JSON_SCHEMA = {
        "type": "object",
        "properties": {"attribute": {"type": "string"}, "value": {"type": "string"}},
        "required": ["attribute", "value"],
    }


class SSOConfig(Config):
    """SSO Configuration"""

    section = "sso"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        sso_config: dict[str, Any] = config.get("sso") or {}

        # Read templates from disk
        (
            self.sso_login_idp_picker_template,
            self.sso_redirect_confirm_template,
            self.sso_auth_confirm_template,
            self.sso_error_template,
            sso_account_deactivated_template,
            sso_auth_success_template,
            self.sso_auth_bad_user_template,
        ) = self.read_templates(
            [
                "sso_login_idp_picker.html",
                "sso_redirect_confirm.html",
                "sso_auth_confirm.html",
                "sso_error.html",
                "sso_account_deactivated.html",
                "sso_auth_success.html",
                "sso_auth_bad_user.html",
            ],
            self.root.server.custom_template_directory,
        )

        # These templates have no placeholders, so render them here
        self.sso_account_deactivated_template = (
            sso_account_deactivated_template.render()
        )
        self.sso_auth_success_template = sso_auth_success_template.render()

        self.sso_client_whitelist = sso_config.get("client_whitelist") or []

        self.sso_update_profile_information = (
            sso_config.get("update_profile_information") or False
        )

        # Attempt to also whitelist the server's login fallback, since that fallback sets
        # the redirect URL to itself (so it can process the login token then return
        # gracefully to the client). This would make it pointless to ask the user for
        # confirmation, since the URL the confirmation page would be showing wouldn't be
        # the client's.
        login_fallback_url = (
            self.root.server.public_baseurl + "_matrix/static/client/login"
        )
        self.sso_client_whitelist.append(login_fallback_url)
