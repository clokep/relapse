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


# This file provides some classes for setting up (partially-populated)
# homeservers; either as a full homeserver as a real application, or a small
# partial one for unit test mocking.


import abc
import functools
import logging
from typing import TYPE_CHECKING, Any, Callable, Optional, TypeVar, cast

from typing_extensions import TypeAlias

from twisted.internet.interfaces import IOpenSSLContextFactory
from twisted.internet.tcp import Port
from twisted.web.iweb import IPolicyForHTTPS
from twisted.web.resource import Resource

from relapse.api.auth import Auth
from relapse.api.auth.internal import InternalAuth
from relapse.api.auth_blocking import AuthBlocking
from relapse.api.filtering import Filtering
from relapse.api.ratelimiting import Ratelimiter, RequestRatelimiter
from relapse.appservice.api import ApplicationServiceApi
from relapse.appservice.scheduler import ApplicationServiceScheduler
from relapse.config.homeserver import HomeServerConfig
from relapse.crypto import context_factory
from relapse.crypto.context_factory import RegularPolicyForHTTPS
from relapse.crypto.keyring import Keyring
from relapse.events.builder import EventBuilderFactory
from relapse.events.presence_router import PresenceRouter
from relapse.events.utils import EventClientSerializer
from relapse.federation.federation_client import FederationClient
from relapse.federation.federation_server import (
    FederationHandlerRegistry,
    FederationServer,
)
from relapse.federation.send_queue import FederationRemoteSendQueue
from relapse.federation.sender import AbstractFederationSender, FederationSender
from relapse.federation.transport.client import TransportLayerClient
from relapse.handlers.account import AccountHandler
from relapse.handlers.account_data import AccountDataHandler
from relapse.handlers.account_validity import AccountValidityHandler
from relapse.handlers.admin import AdminHandler
from relapse.handlers.appservice import ApplicationServicesHandler
from relapse.handlers.auth import AuthHandler, PasswordAuthProvider
from relapse.handlers.cas import CasHandler
from relapse.handlers.deactivate_account import DeactivateAccountHandler
from relapse.handlers.device import DeviceHandler, DeviceWorkerHandler
from relapse.handlers.devicemessage import DeviceMessageHandler
from relapse.handlers.directory import DirectoryHandler
from relapse.handlers.e2e_keys import E2eKeysHandler
from relapse.handlers.e2e_room_keys import E2eRoomKeysHandler
from relapse.handlers.event_auth import EventAuthHandler
from relapse.handlers.events import EventHandler, EventStreamHandler
from relapse.handlers.federation import FederationHandler
from relapse.handlers.federation_event import FederationEventHandler
from relapse.handlers.identity import IdentityHandler
from relapse.handlers.initial_sync import InitialSyncHandler
from relapse.handlers.message import EventCreationHandler, MessageHandler
from relapse.handlers.pagination import PaginationHandler
from relapse.handlers.password_policy import PasswordPolicyHandler
from relapse.handlers.presence import (
    BasePresenceHandler,
    PresenceHandler,
    WorkerPresenceHandler,
)
from relapse.handlers.profile import ProfileHandler
from relapse.handlers.push_rules import PushRulesHandler
from relapse.handlers.read_marker import ReadMarkerHandler
from relapse.handlers.receipts import ReceiptsHandler
from relapse.handlers.register import RegistrationHandler
from relapse.handlers.relations import RelationsHandler
from relapse.handlers.room import (
    RoomContextHandler,
    RoomCreationHandler,
    RoomShutdownHandler,
    TimestampLookupHandler,
)
from relapse.handlers.room_list import RoomListHandler
from relapse.handlers.room_member import (
    RoomForgetterHandler,
    RoomMemberHandler,
    RoomMemberMasterHandler,
)
from relapse.handlers.room_member_worker import RoomMemberWorkerHandler
from relapse.handlers.room_summary import RoomSummaryHandler
from relapse.handlers.search import SearchHandler
from relapse.handlers.send_email import SendEmailHandler
from relapse.handlers.set_password import SetPasswordHandler
from relapse.handlers.sso import SsoHandler
from relapse.handlers.stats import StatsHandler
from relapse.handlers.sync import SyncHandler
from relapse.handlers.typing import FollowerTypingHandler, TypingWriterHandler
from relapse.handlers.user_directory import UserDirectoryHandler
from relapse.handlers.worker_lock import WorkerLocksHandler
from relapse.http.client import (
    InsecureInterceptableContextFactory,
    ReplicationClient,
    SimpleHttpClient,
)
from relapse.http.matrixfederationclient import MatrixFederationHttpClient
from relapse.media.media_repository import MediaRepository
from relapse.metrics.common_usage_metrics import CommonUsageMetricsManager
from relapse.module_api import ModuleApi
from relapse.module_api.callbacks import ModuleApiCallbacks
from relapse.notifier import Notifier, ReplicationNotifier
from relapse.push.bulk_push_rule_evaluator import BulkPushRuleEvaluator
from relapse.push.pusherpool import PusherPool
from relapse.replication.tcp.client import ReplicationDataHandler
from relapse.replication.tcp.external_cache import ExternalCache
from relapse.replication.tcp.handler import ReplicationCommandHandler
from relapse.replication.tcp.resource import ReplicationStreamer
from relapse.replication.tcp.streams import STREAMS_MAP, Stream
from relapse.rest.media.media_repository_resource import MediaRepositoryResource
from relapse.server_notices.server_notices_manager import ServerNoticesManager
from relapse.server_notices.server_notices_sender import ServerNoticesSender
from relapse.server_notices.worker_server_notices_sender import (
    WorkerServerNoticesSender,
)
from relapse.state import StateHandler, StateResolutionHandler
from relapse.storage import Databases
from relapse.storage.controllers import StorageControllers
from relapse.streams.events import EventSources
from relapse.types import DomainSpecificString, IRelapseReactor
from relapse.util import Clock
from relapse.util.distributor import Distributor
from relapse.util.macaroons import MacaroonGenerator
from relapse.util.ratelimitutils import FederationRateLimiter
from relapse.util.stringutils import random_string
from relapse.util.task_scheduler import TaskScheduler

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from txredisapi import ConnectionHandler

    from relapse.handlers.jwt import JwtHandler
    from relapse.handlers.oidc import OidcHandler
    from relapse.handlers.saml import SamlHandler


# The annotation for `cache_in_self` used to be
#     def (builder: Callable[["HomeServer"],T]) -> Callable[["HomeServer"],T]
# which mypy was happy with.
#
# But PyCharm was confused by this. If `foo` was decorated by `@cache_in_self`, then
# an expression like `hs.foo()`
#
# - would erroneously warn that we hadn't provided a `hs` argument to foo (PyCharm
#   confused about boundmethods and unbound methods?), and
# - would be considered to have type `Any`, making for a poor autocomplete and
#   cross-referencing experience.
#
# Instead, use a typevar `F` to express that `@cache_in_self` returns exactly the
# same type it receives. This isn't strictly true [*], but it's more than good
# enough to keep PyCharm and mypy happy.
#
# [*]: (e.g. `builder` could be an object with a __call__ attribute rather than a
#      types.FunctionType instance, whereas the return value is always a
#      types.FunctionType instance.)

T: TypeAlias = object
F = TypeVar("F", bound=Callable[["HomeServer"], T])


def cache_in_self(builder: F) -> F:
    """Wraps a function called e.g. `get_foo`, checking if `self.foo` exists and
    returning if so. If not, calls the given function and sets `self.foo` to it.

    Also ensures that dependency cycles throw an exception correctly, rather
    than overflowing the stack.
    """

    if not builder.__name__.startswith("get_"):
        raise Exception(
            "@cache_in_self can only be used on functions starting with `get_`"
        )

    # get_attr -> _attr
    depname = builder.__name__[len("get") :]

    building = [False]

    @functools.wraps(builder)
    def _get(self: "HomeServer") -> T:
        try:
            return getattr(self, depname)
        except AttributeError:
            pass

        # Prevent cyclic dependencies from deadlocking
        if building[0]:
            raise ValueError("Cyclic dependency while building %s" % (depname,))

        building[0] = True
        try:
            dep = builder(self)
            setattr(self, depname, dep)
        finally:
            building[0] = False

        return dep

    return cast(F, _get)


class HomeServer(metaclass=abc.ABCMeta):
    """A basic homeserver object without lazy component builders.

    This will need all of the components it requires to either be passed as
    constructor arguments, or the relevant methods overriding to create them.
    Typically this would only be used for unit tests.

    Dependencies should be added by creating a `def get_<depname>(self)`
    function, wrapping it in `@cache_in_self`.

    Attributes:
        config (relapse.config.homeserver.HomeserverConfig):
        _listening_services (list[Port]): TCP ports that
            we are listening on to provide HTTP services.
    """

    REQUIRED_ON_BACKGROUND_TASK_STARTUP = [
        "account_validity",
        "auth",
        "deactivate_account",
        "message",
        "pagination",
        "profile",
        "room_forgetter",
        "stats",
    ]

    # This is overridden in derived application classes
    # (such as relapse.app.homeserver.RelapseHomeServer) and gives the class to be
    # instantiated during setup() for future return by get_datastores()
    @property
    @abc.abstractmethod
    def DATASTORE_CLASS(self) -> Any: ...

    def __init__(
        self,
        hostname: str,
        config: HomeServerConfig,
        reactor: Optional[IRelapseReactor] = None,
        version_string: str = "Relapse",
    ):
        """
        Args:
            hostname : The hostname for the server.
            config: The full config for the homeserver.
        """
        if not reactor:
            from twisted.internet import reactor as _reactor

            reactor = cast(IRelapseReactor, _reactor)

        self._reactor = reactor
        self.hostname = hostname
        # the key we use to sign events and requests
        self.signing_key = config.key.signing_key[0]
        self.config = config
        self._listening_services: list[Port] = []
        self.start_time: Optional[int] = None

        self._instance_id = random_string(5)
        self._instance_name = config.worker.instance_name

        self.version_string = version_string

        self.datastores: Optional[Databases] = None

        self._module_web_resources: dict[str, Resource] = {}
        self._module_web_resources_consumed = False

        # This attribute is set by the free function `refresh_certificate`.
        self.tls_server_context_factory: Optional[IOpenSSLContextFactory] = None

    def register_module_web_resource(self, path: str, resource: Resource) -> None:
        """Allows a module to register a web resource to be served at the given path.

        If multiple modules register a resource for the same path, the module that
        appears the highest in the configuration file takes priority.

        Args:
            path: The path to register the resource for.
            resource: The resource to attach to this path.

        Raises:
            RelapseError(500): A module tried to register a web resource after the HTTP
                listeners have been started.
        """
        if self._module_web_resources_consumed:
            raise RuntimeError(
                "Tried to register a web resource from a module after startup",
            )

        # Don't register a resource that's already been registered.
        if path not in self._module_web_resources.keys():
            self._module_web_resources[path] = resource
        else:
            logger.warning(
                "Module tried to register a web resource for path %s but another module"
                " has already registered a resource for this path.",
                path,
            )

    def get_instance_id(self) -> str:
        """A unique ID for this relapse process instance.

        This is used to distinguish running instances in worker-based
        deployments.
        """
        return self._instance_id

    def get_instance_name(self) -> str:
        """A unique name for this relapse process.

        Used to identify the process over replication and in config. Does not
        change over restarts.
        """
        return self._instance_name

    def setup(self) -> None:
        logger.info("Setting up.")
        self.start_time = int(self.get_clock().time())
        self.datastores = Databases(self.DATASTORE_CLASS, self)
        logger.info("Finished setting up.")

        # Register background tasks required by this server. This must be done
        # somewhat manually due to the background tasks not being registered
        # unless handlers are instantiated.
        if self.config.worker.run_background_tasks:
            self.setup_background_tasks()

    def start_listening(self) -> None:  # noqa: B027 (no-op by design)
        """Start the HTTP, manhole, metrics, etc listeners

        Does nothing in this base class; overridden in derived classes to start the
        appropriate listeners.
        """

    def setup_background_tasks(self) -> None:
        """
        Some handlers have side effects on instantiation (like registering
        background updates). This function causes them to be fetched, and
        therefore instantiated, to run those side effects.
        """
        for i in self.REQUIRED_ON_BACKGROUND_TASK_STARTUP:
            getattr(self, "get_" + i + "_handler")()
        self.get_task_scheduler()

    def get_reactor(self) -> IRelapseReactor:
        """
        Fetch the Twisted reactor in use by this HomeServer.
        """
        return self._reactor

    def is_mine(self, domain_specific_string: DomainSpecificString) -> bool:
        return domain_specific_string.domain == self.hostname

    def is_mine_id(self, string: str) -> bool:
        """Determines whether a user ID or room alias originates from this homeserver.

        Returns:
            `True` if the hostname part of the user ID or room alias matches this
            homeserver.
            `False` otherwise, or if the user ID or room alias is malformed.
        """
        localpart_hostname = string.split(":", 1)
        if len(localpart_hostname) < 2:
            return False
        return localpart_hostname[1] == self.hostname

    def is_mine_server_name(self, server_name: str) -> bool:
        """Determines whether a server name refers to this homeserver."""
        return server_name == self.hostname

    @cache_in_self
    def get_clock(self) -> Clock:
        return Clock(self._reactor)

    def get_datastores(self) -> Databases:
        if not self.datastores:
            raise Exception("HomeServer.setup must be called before getting datastores")

        return self.datastores

    @cache_in_self
    def get_distributor(self) -> Distributor:
        return Distributor()

    @cache_in_self
    def get_registration_ratelimiter(self) -> Ratelimiter:
        return Ratelimiter(
            store=self.get_datastores().main,
            clock=self.get_clock(),
            cfg=self.config.ratelimiting.rc_registration,
        )

    @cache_in_self
    def get_federation_client(self) -> FederationClient:
        return FederationClient(self)

    @cache_in_self
    def get_federation_server(self) -> FederationServer:
        return FederationServer(self)

    @cache_in_self
    def get_notifier(self) -> Notifier:
        return Notifier(self)

    @cache_in_self
    def get_replication_notifier(self) -> ReplicationNotifier:
        return ReplicationNotifier()

    @cache_in_self
    def get_auth(self) -> Auth:
        if self.config.experimental.msc3861.enabled:
            from relapse.api.auth.msc3861_delegated import MSC3861DelegatedAuth

            return MSC3861DelegatedAuth(self)
        return InternalAuth(self)

    @cache_in_self
    def get_auth_blocking(self) -> AuthBlocking:
        return AuthBlocking(self)

    @cache_in_self
    def get_http_client_context_factory(self) -> IPolicyForHTTPS:
        if self.config.tls.use_insecure_ssl_client_just_for_testing_do_not_use:
            return InsecureInterceptableContextFactory()
        return RegularPolicyForHTTPS()

    @cache_in_self
    def get_simple_http_client(self) -> SimpleHttpClient:
        """
        An HTTP client with no special configuration.
        """
        return SimpleHttpClient(self)

    @cache_in_self
    def get_proxied_http_client(self) -> SimpleHttpClient:
        """
        An HTTP client that uses configured HTTP(S) proxies.
        """
        return SimpleHttpClient(self, use_proxy=True)

    @cache_in_self
    def get_proxied_blocklisted_http_client(self) -> SimpleHttpClient:
        """
        An HTTP client that uses configured HTTP(S) proxies and blocks IPs
        based on the configured IP ranges.
        """
        return SimpleHttpClient(
            self,
            ip_allowlist=self.config.server.ip_range_allowlist,
            ip_blocklist=self.config.server.ip_range_blocklist,
            use_proxy=True,
        )

    @cache_in_self
    def get_federation_http_client(self) -> MatrixFederationHttpClient:
        """
        An HTTP client for federation.
        """
        tls_client_options_factory = context_factory.FederationPolicyForHTTPS(
            self.config
        )
        return MatrixFederationHttpClient(self, tls_client_options_factory)

    @cache_in_self
    def get_replication_client(self) -> ReplicationClient:
        """
        An HTTP client for HTTP replication.
        """
        return ReplicationClient(self)

    @cache_in_self
    def get_room_creation_handler(self) -> RoomCreationHandler:
        return RoomCreationHandler(self)

    @cache_in_self
    def get_room_shutdown_handler(self) -> RoomShutdownHandler:
        return RoomShutdownHandler(self)

    @cache_in_self
    def get_state_handler(self) -> StateHandler:
        return StateHandler(self)

    @cache_in_self
    def get_state_resolution_handler(self) -> StateResolutionHandler:
        return StateResolutionHandler(self)

    @cache_in_self
    def get_presence_handler(self) -> BasePresenceHandler:
        if self.get_instance_name() in self.config.worker.writers.presence:
            return PresenceHandler(self)
        else:
            return WorkerPresenceHandler(self)

    @cache_in_self
    def get_typing_writer_handler(self) -> TypingWriterHandler:
        if self.get_instance_name() in self.config.worker.writers.typing:
            return TypingWriterHandler(self)
        else:
            raise Exception("Workers cannot write typing")

    @cache_in_self
    def get_presence_router(self) -> PresenceRouter:
        return PresenceRouter(self)

    @cache_in_self
    def get_typing_handler(self) -> FollowerTypingHandler:
        if self.get_instance_name() in self.config.worker.writers.typing:
            # Use get_typing_writer_handler to ensure that we use the same
            # cached version.
            return self.get_typing_writer_handler()
        else:
            return FollowerTypingHandler(self)

    @cache_in_self
    def get_sso_handler(self) -> SsoHandler:
        return SsoHandler(self)

    @cache_in_self
    def get_jwt_handler(self) -> "JwtHandler":
        from relapse.handlers.jwt import JwtHandler

        return JwtHandler(self)

    @cache_in_self
    def get_sync_handler(self) -> SyncHandler:
        return SyncHandler(self)

    @cache_in_self
    def get_room_list_handler(self) -> RoomListHandler:
        return RoomListHandler(self)

    @cache_in_self
    def get_auth_handler(self) -> AuthHandler:
        return AuthHandler(self)

    @cache_in_self
    def get_macaroon_generator(self) -> MacaroonGenerator:
        return MacaroonGenerator(
            self.get_clock(), self.hostname, self.config.key.macaroon_secret_key
        )

    @cache_in_self
    def get_device_handler(self) -> DeviceWorkerHandler:
        if self.config.worker.worker_app:
            return DeviceWorkerHandler(self)
        else:
            return DeviceHandler(self)

    @cache_in_self
    def get_device_message_handler(self) -> DeviceMessageHandler:
        return DeviceMessageHandler(self)

    @cache_in_self
    def get_directory_handler(self) -> DirectoryHandler:
        return DirectoryHandler(self)

    @cache_in_self
    def get_e2e_keys_handler(self) -> E2eKeysHandler:
        return E2eKeysHandler(self)

    @cache_in_self
    def get_e2e_room_keys_handler(self) -> E2eRoomKeysHandler:
        return E2eRoomKeysHandler(self)

    @cache_in_self
    def get_admin_handler(self) -> AdminHandler:
        return AdminHandler(self)

    @cache_in_self
    def get_application_service_api(self) -> ApplicationServiceApi:
        return ApplicationServiceApi(self)

    @cache_in_self
    def get_application_service_scheduler(self) -> ApplicationServiceScheduler:
        return ApplicationServiceScheduler(self)

    @cache_in_self
    def get_application_service_handler(self) -> ApplicationServicesHandler:
        return ApplicationServicesHandler(self)

    @cache_in_self
    def get_event_handler(self) -> EventHandler:
        return EventHandler(self)

    @cache_in_self
    def get_event_stream_handler(self) -> EventStreamHandler:
        return EventStreamHandler(self)

    @cache_in_self
    def get_federation_handler(self) -> FederationHandler:
        return FederationHandler(self)

    @cache_in_self
    def get_federation_event_handler(self) -> FederationEventHandler:
        return FederationEventHandler(self)

    @cache_in_self
    def get_identity_handler(self) -> IdentityHandler:
        return IdentityHandler(self)

    @cache_in_self
    def get_initial_sync_handler(self) -> InitialSyncHandler:
        return InitialSyncHandler(self)

    @cache_in_self
    def get_profile_handler(self) -> ProfileHandler:
        return ProfileHandler(self)

    @cache_in_self
    def get_event_creation_handler(self) -> EventCreationHandler:
        return EventCreationHandler(self)

    @cache_in_self
    def get_deactivate_account_handler(self) -> DeactivateAccountHandler:
        return DeactivateAccountHandler(self)

    @cache_in_self
    def get_search_handler(self) -> SearchHandler:
        return SearchHandler(self)

    @cache_in_self
    def get_send_email_handler(self) -> SendEmailHandler:
        return SendEmailHandler(self)

    @cache_in_self
    def get_set_password_handler(self) -> SetPasswordHandler:
        return SetPasswordHandler(self)

    @cache_in_self
    def get_event_sources(self) -> EventSources:
        return EventSources(self)

    @cache_in_self
    def get_keyring(self) -> Keyring:
        return Keyring(self)

    @cache_in_self
    def get_event_builder_factory(self) -> EventBuilderFactory:
        return EventBuilderFactory(self)

    @cache_in_self
    def get_filtering(self) -> Filtering:
        return Filtering(self)

    @cache_in_self
    def get_pusherpool(self) -> PusherPool:
        return PusherPool(self)

    @cache_in_self
    def get_media_repository_resource(self) -> MediaRepositoryResource:
        # build the media repo resource. This indirects through the HomeServer
        # to ensure that we only have a single instance of
        return MediaRepositoryResource(self)

    @cache_in_self
    def get_media_repository(self) -> MediaRepository:
        return MediaRepository(self)

    @cache_in_self
    def get_federation_transport_client(self) -> TransportLayerClient:
        return TransportLayerClient(self)

    @cache_in_self
    def get_federation_sender(self) -> AbstractFederationSender:
        if self.should_send_federation():
            return FederationSender(self)
        elif not self.config.worker.worker_app:
            return FederationRemoteSendQueue(self)
        else:
            raise Exception("Workers cannot send federation traffic")

    @cache_in_self
    def get_receipts_handler(self) -> ReceiptsHandler:
        return ReceiptsHandler(self)

    @cache_in_self
    def get_read_marker_handler(self) -> ReadMarkerHandler:
        return ReadMarkerHandler(self)

    @cache_in_self
    def get_replication_command_handler(self) -> ReplicationCommandHandler:
        return ReplicationCommandHandler(self)

    @cache_in_self
    def get_bulk_push_rule_evaluator(self) -> BulkPushRuleEvaluator:
        return BulkPushRuleEvaluator(self)

    @cache_in_self
    def get_user_directory_handler(self) -> UserDirectoryHandler:
        return UserDirectoryHandler(self)

    @cache_in_self
    def get_stats_handler(self) -> StatsHandler:
        return StatsHandler(self)

    @cache_in_self
    def get_password_auth_provider(self) -> PasswordAuthProvider:
        return PasswordAuthProvider()

    @cache_in_self
    def get_room_member_handler(self) -> RoomMemberHandler:
        if self.config.worker.worker_app:
            return RoomMemberWorkerHandler(self)
        return RoomMemberMasterHandler(self)

    @cache_in_self
    def get_federation_registry(self) -> FederationHandlerRegistry:
        return FederationHandlerRegistry(self)

    @cache_in_self
    def get_server_notices_manager(self) -> ServerNoticesManager:
        if self.config.worker.worker_app:
            raise Exception("Workers cannot send server notices")
        return ServerNoticesManager(self)

    @cache_in_self
    def get_server_notices_sender(self) -> WorkerServerNoticesSender:
        if self.config.worker.worker_app:
            return WorkerServerNoticesSender(self)
        return ServerNoticesSender(self)

    @cache_in_self
    def get_message_handler(self) -> MessageHandler:
        return MessageHandler(self)

    @cache_in_self
    def get_pagination_handler(self) -> PaginationHandler:
        return PaginationHandler(self)

    @cache_in_self
    def get_relations_handler(self) -> RelationsHandler:
        return RelationsHandler(self)

    @cache_in_self
    def get_room_context_handler(self) -> RoomContextHandler:
        return RoomContextHandler(self)

    @cache_in_self
    def get_timestamp_lookup_handler(self) -> TimestampLookupHandler:
        return TimestampLookupHandler(self)

    @cache_in_self
    def get_registration_handler(self) -> RegistrationHandler:
        return RegistrationHandler(self)

    @cache_in_self
    def get_account_validity_handler(self) -> AccountValidityHandler:
        return AccountValidityHandler(self)

    @cache_in_self
    def get_cas_handler(self) -> CasHandler:
        return CasHandler(self)

    @cache_in_self
    def get_saml_handler(self) -> "SamlHandler":
        from relapse.handlers.saml import SamlHandler

        return SamlHandler(self)

    @cache_in_self
    def get_oidc_handler(self) -> "OidcHandler":
        from relapse.handlers.oidc import OidcHandler

        return OidcHandler(self)

    @cache_in_self
    def get_event_client_serializer(self) -> EventClientSerializer:
        return EventClientSerializer(self)

    @cache_in_self
    def get_password_policy_handler(self) -> PasswordPolicyHandler:
        return PasswordPolicyHandler(self)

    @cache_in_self
    def get_storage_controllers(self) -> StorageControllers:
        return StorageControllers(self, self.get_datastores())

    @cache_in_self
    def get_replication_streamer(self) -> ReplicationStreamer:
        return ReplicationStreamer(self)

    @cache_in_self
    def get_replication_data_handler(self) -> ReplicationDataHandler:
        return ReplicationDataHandler(self)

    @cache_in_self
    def get_replication_streams(self) -> dict[str, Stream]:
        return {stream.NAME: stream(self) for stream in STREAMS_MAP.values()}

    @cache_in_self
    def get_federation_ratelimiter(self) -> FederationRateLimiter:
        return FederationRateLimiter(
            self.get_clock(),
            config=self.config.ratelimiting.rc_federation,
            metrics_name="federation_servlets",
        )

    @cache_in_self
    def get_module_api(self) -> ModuleApi:
        return ModuleApi(self, self.get_auth_handler())

    @cache_in_self
    def get_module_api_callbacks(self) -> ModuleApiCallbacks:
        return ModuleApiCallbacks(self)

    @cache_in_self
    def get_account_data_handler(self) -> AccountDataHandler:
        return AccountDataHandler(self)

    @cache_in_self
    def get_room_summary_handler(self) -> RoomSummaryHandler:
        return RoomSummaryHandler(self)

    @cache_in_self
    def get_event_auth_handler(self) -> EventAuthHandler:
        return EventAuthHandler(self)

    @cache_in_self
    def get_external_cache(self) -> ExternalCache:
        return ExternalCache(self)

    @cache_in_self
    def get_account_handler(self) -> AccountHandler:
        return AccountHandler(self)

    @cache_in_self
    def get_push_rules_handler(self) -> PushRulesHandler:
        return PushRulesHandler(self)

    @cache_in_self
    def get_room_forgetter_handler(self) -> RoomForgetterHandler:
        return RoomForgetterHandler(self)

    @cache_in_self
    def get_outbound_redis_connection(self) -> "ConnectionHandler":
        """
        The Redis connection used for replication.

        Raises:
            AssertionError: if Redis is not enabled in the homeserver config.
        """
        assert self.config.redis.redis_enabled

        # We only want to import redis module if we're using it, as we have
        # `txredisapi` as an optional dependency.
        from relapse.replication.tcp.redis import lazyConnection, lazyUnixConnection

        if self.config.redis.redis_path is None:
            logger.info(
                "Connecting to redis (host=%r port=%r) for external cache",
                self.config.redis.redis_host,
                self.config.redis.redis_port,
            )

            return lazyConnection(
                hs=self,
                host=self.config.redis.redis_host,
                port=self.config.redis.redis_port,
                dbid=self.config.redis.redis_dbid,
                password=self.config.redis.redis_password,
                reconnect=True,
            )
        else:
            logger.info(
                "Connecting to redis (path=%r) for external cache",
                self.config.redis.redis_path,
            )

            return lazyUnixConnection(
                hs=self,
                path=self.config.redis.redis_path,
                dbid=self.config.redis.redis_dbid,
                password=self.config.redis.redis_password,
                reconnect=True,
            )

    def should_send_federation(self) -> bool:
        "Should this server be sending federation traffic directly?"
        return self.config.worker.send_federation

    @cache_in_self
    def get_request_ratelimiter(self) -> RequestRatelimiter:
        return RequestRatelimiter(
            self.get_datastores().main,
            self.get_clock(),
            self.config.ratelimiting.rc_message,
            self.config.ratelimiting.rc_admin_redaction,
        )

    @cache_in_self
    def get_common_usage_metrics_manager(self) -> CommonUsageMetricsManager:
        """Usage metrics shared between phone home stats and the prometheus exporter."""
        return CommonUsageMetricsManager(self)

    @cache_in_self
    def get_worker_locks_handler(self) -> WorkerLocksHandler:
        return WorkerLocksHandler(self)

    @cache_in_self
    def get_task_scheduler(self) -> TaskScheduler:
        return TaskScheduler(self)
