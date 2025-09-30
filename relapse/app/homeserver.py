# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2019 New Vector Ltd
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

import logging
import os
import sys
from collections.abc import Iterable

from twisted.internet.tcp import Port
from twisted.web.resource import EncodingResourceWrapper, Resource
from twisted.web.server import GzipEncoderFactory

import relapse
import relapse.config.logger
from relapse import events
from relapse.api.urls import (
    CLIENT_API_PREFIX,
    FEDERATION_PREFIX,
    MEDIA_R0_PREFIX,
    MEDIA_V3_PREFIX,
    SERVER_KEY_PREFIX,
    STATIC_PREFIX,
)
from relapse.app import _base
from relapse.app._base import (
    handle_startup_exception,
    listen_http,
    max_request_body_size,
    redirect_stdio_to_logs,
    register_start,
)
from relapse.config._base import ConfigError, format_config_error
from relapse.config.homeserver import HomeServerConfig
from relapse.config.server import ListenerConfig, TCPListenerConfig
from relapse.http.additional_resource import AdditionalResource
from relapse.http.server import (
    JsonResource,
    OptionsResource,
    RootOptionsRedirectResource,
    StaticResource,
)
from relapse.logging.context import LoggingContext
from relapse.metrics import METRICS_PREFIX, MetricsResource, RegistryProxy
from relapse.replication.http import REPLICATION_PREFIX, ReplicationRestResource
from relapse.rest import client, federation
from relapse.rest.admin import AdminRestResource
from relapse.rest.health import HealthResource
from relapse.rest.key.v2 import KeyResource
from relapse.rest.relapse.client import build_relapse_client_resource_tree
from relapse.rest.well_known import well_known_resource
from relapse.server import HomeServer
from relapse.storage import DataStore
from relapse.util.check_dependencies import VERSION, check_requirements
from relapse.util.httpresourcetree import create_resource_tree
from relapse.util.module_loader import load_module

logger = logging.getLogger("relapse.app.homeserver")


def gz_wrap(r: Resource) -> Resource:
    return EncodingResourceWrapper(r, [GzipEncoderFactory()])


class RelapseHomeServer(HomeServer):
    DATASTORE_CLASS = DataStore

    def _listener_http(
        self,
        config: HomeServerConfig,
        listener_config: ListenerConfig,
    ) -> Iterable[Port]:
        # Must exist since this is an HTTP listener.
        assert listener_config.http_options is not None
        site_tag = listener_config.get_site_tag()

        # We always include a health resource.
        resources: dict[str, Resource] = {"/health": HealthResource()}

        for res in listener_config.http_options.resources:
            for name in res.names:
                if name == "openid" and "federation" in res.names:
                    # Skip loading openid resource if federation is defined
                    # since federation resource will include openid
                    continue
                if name == "health":
                    # Skip loading, health resource is always included
                    continue
                resources.update(self._configure_named_resource(name, res.compress))

        additional_resources = listener_config.http_options.additional_resources
        logger.debug("Configuring additional resources: %r", additional_resources)
        module_api = self.get_module_api()
        for path, resmodule in additional_resources.items():
            handler_cls, config = load_module(
                resmodule,
                ("listeners", site_tag, "additional_resources", "<%s>" % (path,)),
            )
            handler = handler_cls(config, module_api)
            if isinstance(handler, Resource):
                resource = handler
            elif hasattr(handler, "handle_request"):
                resource = AdditionalResource(self, handler.handle_request)
            else:
                raise ConfigError(
                    "additional_resource %s does not implement a known interface"
                    % (resmodule["module"],)
                )
            resources[path] = resource

        # Attach additional resources registered by modules.
        resources.update(self._module_web_resources)
        self._module_web_resources_consumed = True

        # Try to find something useful to serve at '/':
        #
        # 1. Redirect to the web client if it is an HTTP(S) URL.
        # 2. Redirect to the static "Relapse is running" page.
        # 3. Do not redirect and use a blank resource.
        if self.config.server.web_client_location:
            root_resource: Resource = RootOptionsRedirectResource(
                self.config.server.web_client_location
            )
        elif STATIC_PREFIX in resources:
            root_resource = RootOptionsRedirectResource(STATIC_PREFIX)
        else:
            root_resource = OptionsResource()

        ports = listen_http(
            self,
            listener_config,
            create_resource_tree(resources, root_resource),
            self.version_string,
            max_request_body_size(self.config),
            self.tls_server_context_factory,
            reactor=self.get_reactor(),
        )

        return ports

    def _configure_named_resource(
        self, name: str, compress: bool = False
    ) -> dict[str, Resource]:
        """Build a resource map for a named resource

        Args:
            name: named resource: one of "client", "federation", etc
            compress: whether to enable gzip compression for this resource

        Returns:
            map from path to HTTP resource
        """
        resources: dict[str, Resource] = {}
        if name == "client":
            client_server = JsonResource(self, canonical_json=False)
            client.register_servlets(self, client_server)
            client_resource: Resource = client_server
            if compress:
                client_resource = gz_wrap(client_resource)

            resources.update(
                {
                    CLIENT_API_PREFIX: client_resource,
                    "/.well-known": well_known_resource(self),
                    "/_relapse/admin": AdminRestResource(self),
                    **build_relapse_client_resource_tree(self),
                }
            )

            if self.config.email.can_verify_email:
                from relapse.rest.relapse.client.password_reset import (
                    PasswordResetSubmitTokenResource,
                )

                resources["/_relapse/client/password_reset/email/submit_token"] = (
                    PasswordResetSubmitTokenResource(self)
                )

        if name == "consent":
            from relapse.rest.consent.consent_resource import ConsentResource

            consent_resource: Resource = ConsentResource(self)
            if compress:
                consent_resource = gz_wrap(consent_resource)
            resources["/_matrix/consent"] = consent_resource

        if name == "federation":
            federation_server = JsonResource(self, canonical_json=False)
            federation.register_servlets(self, federation_server)
            federation_resource: Resource = federation_server
            if compress:
                federation_resource = gz_wrap(federation_resource)
            resources[FEDERATION_PREFIX] = federation_resource

        if name == "openid":
            federation_resource = JsonResource(self, canonical_json=False)
            federation.register_servlets(
                self, federation_resource, servlet_groups=["openid"]
            )

            resources[FEDERATION_PREFIX] = federation_resource

        if name in ["static", "client"]:
            resources[STATIC_PREFIX] = StaticResource(
                os.path.join(os.path.dirname(relapse.__file__), "static")
            )

        if name in ["media", "federation", "client"]:
            if self.config.server.enable_media_repo:
                media_repo = self.get_media_repository_resource()
                resources.update(
                    {
                        MEDIA_R0_PREFIX: media_repo,
                        MEDIA_V3_PREFIX: media_repo,
                    }
                )
            elif name == "media":
                raise ConfigError(
                    "'media' resource conflicts with enable_media_repo=False"
                )

        if name in ["keys", "federation"]:
            resources[SERVER_KEY_PREFIX] = KeyResource(self)

        if name == "metrics" and self.config.metrics.enable_metrics:
            metrics_resource: Resource = MetricsResource(RegistryProxy)
            if compress:
                metrics_resource = gz_wrap(metrics_resource)
            resources[METRICS_PREFIX] = metrics_resource

        if name == "replication":
            resources[REPLICATION_PREFIX] = ReplicationRestResource(self)

        return resources

    def start_listening(self) -> None:
        if self.config.redis.redis_enabled:
            # If redis is enabled we connect via the replication command handler
            # in the same way as the workers (since we're effectively a client
            # rather than a server).
            self.get_replication_command_handler().start_replication(self)

        for listener in self.config.server.listeners:
            if listener.type == "http":
                self._listening_services.extend(
                    self._listener_http(self.config, listener)
                )
            elif listener.type == "manhole":
                if isinstance(listener, TCPListenerConfig):
                    _base.listen_manhole(
                        listener.bind_addresses,
                        listener.port,
                        manhole_settings=self.config.server.manhole_settings,
                        manhole_globals={"hs": self},
                    )
                else:
                    raise ConfigError(
                        "Can not use a unix socket for manhole at this time."
                    )
            elif listener.type == "metrics":
                if not self.config.metrics.enable_metrics:
                    logger.warning(
                        "Metrics listener configured, but enable_metrics is not True!"
                    )
                else:
                    if isinstance(listener, TCPListenerConfig):
                        _base.listen_metrics(
                            listener.bind_addresses,
                            listener.port,
                        )
                    else:
                        raise ConfigError(
                            "Can not use a unix socket for metrics at this time."
                        )

            else:
                # this shouldn't happen, as the listener type should have been checked
                # during parsing
                logger.warning("Unrecognized listener type: %s", listener.type)


def setup(config_options: list[str]) -> RelapseHomeServer:
    """
    Args:
        config_options_options: The options passed to Relapse. Usually `sys.argv[1:]`.

    Returns:
        A homeserver instance.
    """
    try:
        config = HomeServerConfig.load_or_generate_config(
            "Relapse Homeserver", config_options
        )
    except ConfigError as e:
        sys.stderr.write("\n")
        for f in format_config_error(e):
            sys.stderr.write(f)
        sys.stderr.write("\n")
        sys.exit(1)

    if not config:
        # If a config isn't returned, and an exception isn't raised, we're just
        # generating config files and shouldn't try to continue.
        sys.exit(0)

    if config.worker.worker_app:
        raise ConfigError(
            "You have specified `worker_app` in the config but are attempting to start a non-worker "
            "instance. Please use `python -m relapse.app.generic_worker` instead (or remove the option if this is the main process)."
        )
        sys.exit(1)

    events.USE_FROZEN_DICTS = config.server.use_frozen_dicts
    relapse.util.caches.TRACK_MEMORY_USAGE = config.caches.track_memory_usage

    if config.server.gc_seconds:
        relapse.metrics.MIN_TIME_BETWEEN_GCS = config.server.gc_seconds

    if (
        config.registration.enable_registration
        and not config.registration.enable_registration_without_verification
    ):
        if (
            not config.captcha.enable_registration_captcha
            and not config.registration.registrations_require_3pid
            and not config.registration.registration_requires_token
        ):
            raise ConfigError(
                "You have enabled open registration without any verification. This is a known vector for "
                "spam and abuse. If you would like to allow public registration, please consider adding email, "
                "captcha, or token-based verification. Otherwise this check can be removed by setting the "
                "`enable_registration_without_verification` config option to `true`."
            )

    hs = RelapseHomeServer(
        config.server.server_name,
        config=config,
        version_string=f"Relapse/{VERSION}",
    )

    relapse.config.logger.setup_logging(hs, config, use_worker_options=False)

    logger.info("Setting up server")

    try:
        hs.setup()
    except Exception as e:
        handle_startup_exception(e)

    async def start() -> None:
        # Load the OIDC provider metadatas, if OIDC is enabled.
        if hs.config.oidc.oidc_enabled:
            oidc = hs.get_oidc_handler()
            # Loading the provider metadata also ensures the provider config is valid.
            await oidc.load_metadata()

        await _base.start(hs)

        hs.get_datastores().main.db_pool.updates.start_doing_background_updates()

    register_start(start)

    return hs


def run(hs: HomeServer) -> None:
    _base.start_reactor(
        "relapse-homeserver",
        soft_file_limit=hs.config.server.soft_file_limit,
        gc_thresholds=hs.config.server.gc_thresholds,
        pid_file=hs.config.server.pid_file,
        daemonize=hs.config.server.daemonize,
        print_pidfile=hs.config.server.print_pidfile,
        logger=logger,
    )


def main() -> None:
    with LoggingContext("main"):
        # check base requirements
        check_requirements()
        hs = setup(sys.argv[1:])

        # redirect stdio to the logs, if configured.
        if not hs.config.logging.no_redirect_stdio:
            redirect_stdio_to_logs()

        run(hs)


if __name__ == "__main__":
    main()
