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

from collections.abc import Mapping
from typing import TYPE_CHECKING

from twisted.web.resource import Resource

from relapse.http.server import JsonResource
from relapse.rest.relapse.client.new_user_consent import NewUserConsentResource
from relapse.rest.relapse.client.pick_idp import PickIdpResource
from relapse.rest.relapse.client.pick_username import pick_username_resource
from relapse.rest.relapse.client.sso_register import SsoRegisterResource
from relapse.rest.relapse.client.unsubscribe import UnsubscribeResource

if TYPE_CHECKING:
    from relapse.server import HomeServer


def build_relapse_client_resource_tree(hs: "HomeServer") -> Mapping[str, Resource]:
    """Builds a resource tree to include relapse-specific client resources

    These are resources which should be loaded on all workers which expose a C-S API:
    ie, the main process, and any generic workers so configured.

    Returns:
         map from path to Resource.
    """
    resources = {
        # SSO bits. These are always loaded, whether or not SSO login is actually
        # enabled (they just won't work very well if it's not)
        "/_relapse/client/pick_idp": PickIdpResource(hs),
        "/_relapse/client/pick_username": pick_username_resource(hs),
        "/_relapse/client/new_user_consent": NewUserConsentResource(hs),
        "/_relapse/client/sso_register": SsoRegisterResource(hs),
        # Unsubscribe to notification emails link
        "/_relapse/client/unsubscribe": UnsubscribeResource(hs),
    }

    # Expose the JWKS endpoint if OAuth2 delegation is enabled
    if hs.config.experimental.msc3861.enabled:
        from relapse.rest.relapse.client.jwks import JwksServlet

        resource = JsonResource(hs, canonical_json=False)
        JwksServlet(hs).register(resource)
        resources["/_relapse/jwks"] = resource

    # provider-specific SSO bits. Only load these if they are enabled, since they
    # rely on optional dependencies.
    if hs.config.oidc.oidc_enabled:
        from relapse.rest.relapse.client.oidc import (
            OIDCBackchannelLogoutServlet,
            OIDCCallbackServlet,
        )

        resource = JsonResource(hs, canonical_json=False)
        OIDCCallbackServlet(hs).register(resource)
        OIDCBackchannelLogoutServlet(hs).register(resource)
        resources["/_relapse/client/oidc"] = resource

    if hs.config.saml2.saml2_enabled:
        from relapse.rest.relapse.client.saml2 import SAML2Resource

        res = SAML2Resource(hs)
        resources["/_relapse/client/saml2"] = res

    return resources


__all__ = ["build_relapse_client_resource_tree"]
