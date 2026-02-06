# Copyright 2016 OpenMarket Ltd
# Copyright 2020 The Matrix.org Foundation C.I.C.
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
import sys
from collections.abc import Iterable

from twisted.internet.tcp import Port
from twisted.web.resource import Resource

import relapse
import relapse.events
from relapse.api.urls import (
    CLIENT_API_PREFIX,
    FEDERATION_PREFIX,
    MEDIA_R0_PREFIX,
    MEDIA_V3_PREFIX,
    SERVER_KEY_PREFIX,
)
from relapse.app import _base
from relapse.app._base import (
    handle_startup_exception,
    max_request_body_size,
    redirect_stdio_to_logs,
    register_start,
)
from relapse.config._base import ConfigError
from relapse.config.homeserver import HomeServerConfig
from relapse.config.logger import setup_logging
from relapse.config.server import ListenerConfig, TCPListenerConfig
from relapse.http.server import JsonResource, OptionsResource
from relapse.logging.context import LoggingContext
from relapse.metrics import METRICS_PREFIX, RegistryProxy
from relapse.replication.http import (
    REPLICATION_PREFIX,
    register_servlets as register_replication_servlets,
)
from relapse.rest import client, federation, key, media, well_known
from relapse.rest.admin import register_servlets_for_media_repo
from relapse.rest.health import HealthServlet
from relapse.rest.relapse.client import build_relapse_client_resource_tree
from relapse.rest.relapse.metrics import MetricsServlet
from relapse.server import HomeServer
from relapse.storage.databases.main.account_data import AccountDataWorkerStore
from relapse.storage.databases.main.appservice import (
    ApplicationServiceTransactionWorkerStore,
    ApplicationServiceWorkerStore,
)
from relapse.storage.databases.main.censor_events import CensorEventsStore
from relapse.storage.databases.main.client_ips import ClientIpWorkerStore
from relapse.storage.databases.main.deviceinbox import DeviceInboxWorkerStore
from relapse.storage.databases.main.devices import DeviceWorkerStore
from relapse.storage.databases.main.directory import DirectoryWorkerStore
from relapse.storage.databases.main.e2e_room_keys import EndToEndRoomKeyStore
from relapse.storage.databases.main.event_federation import EventFederationWorkerStore
from relapse.storage.databases.main.event_push_actions import (
    EventPushActionsWorkerStore,
)
from relapse.storage.databases.main.events_worker import EventsWorkerStore
from relapse.storage.databases.main.filtering import FilteringWorkerStore
from relapse.storage.databases.main.keys import KeyStore
from relapse.storage.databases.main.lock import LockStore
from relapse.storage.databases.main.media_repository import MediaRepositoryStore
from relapse.storage.databases.main.metrics import ServerMetricsStore
from relapse.storage.databases.main.monthly_active_users import (
    MonthlyActiveUsersWorkerStore,
)
from relapse.storage.databases.main.presence import PresenceStore
from relapse.storage.databases.main.profile import ProfileWorkerStore
from relapse.storage.databases.main.purge_events import PurgeEventsStore
from relapse.storage.databases.main.push_rule import PushRulesWorkerStore
from relapse.storage.databases.main.pusher import PusherWorkerStore
from relapse.storage.databases.main.receipts import ReceiptsWorkerStore
from relapse.storage.databases.main.registration import RegistrationWorkerStore
from relapse.storage.databases.main.relations import RelationsWorkerStore
from relapse.storage.databases.main.room import RoomWorkerStore
from relapse.storage.databases.main.roommember import RoomMemberWorkerStore
from relapse.storage.databases.main.search import SearchStore
from relapse.storage.databases.main.session import SessionStore
from relapse.storage.databases.main.signatures import SignatureWorkerStore
from relapse.storage.databases.main.state import StateGroupWorkerStore
from relapse.storage.databases.main.stats import StatsStore
from relapse.storage.databases.main.stream import StreamWorkerStore
from relapse.storage.databases.main.tags import TagsWorkerStore
from relapse.storage.databases.main.task_scheduler import TaskSchedulerWorkerStore
from relapse.storage.databases.main.transactions import TransactionWorkerStore
from relapse.storage.databases.main.ui_auth import UIAuthWorkerStore
from relapse.storage.databases.main.user_directory import UserDirectoryStore
from relapse.storage.databases.main.user_erasure_store import UserErasureWorkerStore
from relapse.util import RELAPSE_VERSION
from relapse.util.httpresourcetree import create_resource_tree

logger = logging.getLogger("relapse.app.generic_worker")


class GenericWorkerStore(
    # FIXME(https://github.com/matrix-org/synapse/issues/3714): We need to add
    # UserDirectoryStore as we write directly rather than going via the correct worker.
    UserDirectoryStore,
    StatsStore,
    UIAuthWorkerStore,
    EndToEndRoomKeyStore,
    PresenceStore,
    DeviceInboxWorkerStore,
    DeviceWorkerStore,
    TagsWorkerStore,
    AccountDataWorkerStore,
    CensorEventsStore,
    ClientIpWorkerStore,
    # KeyStore isn't really safe to use from a worker, but for now we do so and hope that
    # the races it creates aren't too bad.
    KeyStore,
    RoomWorkerStore,
    DirectoryWorkerStore,
    PushRulesWorkerStore,
    ApplicationServiceTransactionWorkerStore,
    ApplicationServiceWorkerStore,
    ProfileWorkerStore,
    FilteringWorkerStore,
    MonthlyActiveUsersWorkerStore,
    MediaRepositoryStore,
    ServerMetricsStore,
    PusherWorkerStore,
    RoomMemberWorkerStore,
    RelationsWorkerStore,
    EventFederationWorkerStore,
    EventPushActionsWorkerStore,
    PurgeEventsStore,
    StateGroupWorkerStore,
    SignatureWorkerStore,
    UserErasureWorkerStore,
    ReceiptsWorkerStore,
    StreamWorkerStore,
    EventsWorkerStore,
    RegistrationWorkerStore,
    SearchStore,
    TransactionWorkerStore,
    LockStore,
    SessionStore,
    TaskSchedulerWorkerStore,
):
    # Properties that multiple storage classes define. Tell mypy what the
    # expected type is.
    server_name: str
    config: HomeServerConfig


class GenericWorkerServer(HomeServer):
    DATASTORE_CLASS = GenericWorkerStore

    def listen_http(self, listener_config: ListenerConfig) -> Iterable[Port]:
        assert listener_config.http_options is not None

        # We always include a health resource.
        health_resource = JsonResource(self, canonical_json=False)
        HealthServlet().register(health_resource)
        resources: dict[str, Resource] = {"/health": health_resource}

        for res in listener_config.http_options.resources:
            for name in res.names:
                if name == "metrics":
                    metrics_resource = JsonResource(self, canonical_json=False)
                    MetricsServlet(RegistryProxy).register(metrics_resource)
                    resources[METRICS_PREFIX] = metrics_resource
                elif name == "client":
                    resource = JsonResource(self, canonical_json=False)
                    client.register_servlets(self, resource)
                    resources[CLIENT_API_PREFIX] = resource

                    resources.update(build_relapse_client_resource_tree(self))

                    well_known_resource = JsonResource(self, canonical_json=False)
                    well_known.register_servlets(self, well_known_resource)
                    resources["/.well-known"] = well_known_resource

                elif name == "federation":
                    federation_resource = JsonResource(self, canonical_json=False)
                    federation.register_servlets(self, federation_resource)
                    resources[FEDERATION_PREFIX] = federation_resource
                elif name == "media":
                    if self.config.media.can_load_media_repo:
                        media_resource = JsonResource(self, canonical_json=False)
                        media.register_servlets(self, media_resource)

                        # We need to serve the admin servlets for media on the
                        # worker.
                        admin_resource = JsonResource(self, canonical_json=False)
                        register_servlets_for_media_repo(self, admin_resource)

                        resources.update(
                            {
                                MEDIA_R0_PREFIX: media_resource,
                                MEDIA_V3_PREFIX: media_resource,
                                "/_relapse/admin": admin_resource,
                            }
                        )
                    else:
                        logger.warning(
                            "A 'media' listener is configured but the media"
                            " repository is disabled. Ignoring."
                        )
                elif name == "health":
                    # Skip loading, health resource is always included
                    continue

                if name == "openid" and "federation" not in res.names:
                    # Only load the openid resource separately if federation resource
                    # is not specified since federation resource includes openid
                    # resource.
                    federation_resource = JsonResource(self, canonical_json=False)
                    federation.register_servlets(
                        self, federation_resource, servlet_groups=["openid"]
                    )
                    resources[FEDERATION_PREFIX] = federation_resource

                if name in ["keys", "federation"]:
                    key_resource = JsonResource(self, canonical_json=True)
                    key.register_servlets(self, key_resource)
                    resources[SERVER_KEY_PREFIX] = key_resource

                if name == "replication":
                    replication_resource = JsonResource(self, canonical_json=False)
                    register_replication_servlets(self, replication_resource)
                    resources[REPLICATION_PREFIX] = replication_resource

        # Attach additional resources registered by modules.
        resources.update(self._module_web_resources)
        self._module_web_resources_consumed = True

        root_resource = create_resource_tree(resources, OptionsResource())

        return _base.listen_http(
            self,
            listener_config,
            root_resource,
            self.version_string,
            max_request_body_size(self.config),
            self.tls_server_context_factory,
            reactor=self.get_reactor(),
        )

    def start_listening(self) -> None:
        for listener in self.config.worker.worker_listeners:
            if listener.type == "http":
                self.listen_http(listener)
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
                        "Can not using a unix socket for manhole at this time."
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
                logger.warning("Unsupported listener type: %s", listener.type)

        self.get_replication_command_handler().start_replication(self)


def start(config_options: list[str]) -> None:
    try:
        config = HomeServerConfig.load_config("Relapse worker", config_options)
    except ConfigError as e:
        sys.stderr.write("\n" + str(e) + "\n")
        sys.exit(1)

    relapse.events.USE_FROZEN_DICTS = config.server.use_frozen_dicts
    relapse.util.caches.TRACK_MEMORY_USAGE = config.caches.track_memory_usage

    if config.server.gc_seconds:
        relapse.metrics.MIN_TIME_BETWEEN_GCS = config.server.gc_seconds

    hs = GenericWorkerServer(
        config.server.server_name,
        config=config,
        version_string=f"Relapse/{RELAPSE_VERSION}",
    )

    setup_logging(hs, config, use_worker_options=True)

    try:
        hs.setup()

        # Ensure the replication streamer is always started in case we write to any
        # streams. Will no-op if no streams can be written to by this worker.
        hs.get_replication_streamer()
    except Exception as e:
        handle_startup_exception(e)

    register_start(_base.start, hs)

    # redirect stdio to the logs, if configured.
    if not hs.config.logging.no_redirect_stdio:
        redirect_stdio_to_logs()

    _base.start_worker_reactor("relapse-generic-worker", config)


def main() -> None:
    with LoggingContext("main"):
        start(sys.argv[1:])


if __name__ == "__main__":
    main()
