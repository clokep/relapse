# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2021 The Matrix.org Foundation C.I.C.
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

from typing import Any

from relapse.config.sso import SsoAttributeRequirement
from relapse.types import JsonDict

from ._base import Config, ConfigError
from ._util import validate_config


class CasConfig(Config):
    """Cas Configuration

    cas_server_url: URL of CAS server
    """

    section = "cas"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        cas_config = config.get("cas_config", None)
        self.cas_enabled = cas_config and cas_config.get("enabled", True)

        if self.cas_enabled:
            self.cas_server_url = cas_config["server_url"]

            # TODO Update this to a _relapse URL.
            public_baseurl = self.root.server.public_baseurl
            self.cas_service_url = public_baseurl + "_matrix/client/r0/login/cas/ticket"

            self.cas_protocol_version = cas_config.get("protocol_version")
            if (
                self.cas_protocol_version is not None
                and self.cas_protocol_version not in [1, 2, 3]
            ):
                raise ConfigError(
                    "Unsupported CAS protocol version %s (only versions 1, 2, 3 are supported)"
                    % (self.cas_protocol_version,),
                    ("cas_config", "protocol_version"),
                )
            self.cas_displayname_attribute = cas_config.get("displayname_attribute")
            required_attributes = cas_config.get("required_attributes") or {}
            self.cas_required_attributes = _parsed_required_attributes_def(
                required_attributes
            )

            self.cas_enable_registration = cas_config.get("enable_registration", True)

            self.idp_name = cas_config.get("idp_name", "CAS")
            self.idp_icon = cas_config.get("idp_icon")
            self.idp_brand = cas_config.get("idp_brand")

        else:
            self.cas_server_url = None
            self.cas_service_url = None
            self.cas_protocol_version = None
            self.cas_displayname_attribute = None
            self.cas_required_attributes = []
            self.cas_enable_registration = False


# CAS uses a legacy required attributes mapping, not the one provided by
# SsoAttributeRequirement.
REQUIRED_ATTRIBUTES_SCHEMA = {
    "type": "object",
    "additionalProperties": {"anyOf": [{"type": "string"}, {"type": "null"}]},
}


def _parsed_required_attributes_def(
    required_attributes: Any,
) -> list[SsoAttributeRequirement]:
    validate_config(
        REQUIRED_ATTRIBUTES_SCHEMA,
        required_attributes,
        config_path=("cas_config", "required_attributes"),
    )
    return [SsoAttributeRequirement(k, v) for k, v in required_attributes.items()]
