# Copyright 2016 OpenMarket Ltd
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

import argparse
from typing import Any, Optional, Union

import attr
from pydantic import BaseModel, ConfigDict

from relapse.config._base import (
    Config,
    ConfigError,
    RoutableShardedWorkerHandlingConfig,
    ShardedWorkerHandlingConfig,
)
from relapse.config._util import parse_and_validate_mapping
from relapse.config.server import (
    DIRECT_TCP_ERROR,
    TCPListenerConfig,
    parse_listener_def,
)
from relapse.types import JsonDict

_MISSING_MAIN_PROCESS_INSTANCE_MAP_DATA = """
Missing data for a worker to connect to main process. Please include '%s' in the
`instance_map` declared in your shared yaml configuration as defined in configuration
documentation here:
`https://clokep.github.io/relapse/latest/usage/configuration/config_documentation.html#instance_map`
"""

# This allows for a handy knob when it's time to change from 'master' to
# something with less 'history'
MAIN_PROCESS_INSTANCE_NAME = "master"
# Use this to adjust what the main process is known as in the yaml instance_map
MAIN_PROCESS_INSTANCE_MAP_NAME = "main"


def _instance_to_list_converter(obj: Union[str, list[str]]) -> list[str]:
    """Helper for allowing parsing a string or list of strings to a config
    option expecting a list of strings.
    """

    if isinstance(obj, str):
        return [obj]
    return obj


class ConfigModel(BaseModel):
    """A custom version of Pydantic's BaseModel which

     - ignores unknown fields
     - does not allow fields to be overwritten after construction
     - uses strict conversion of types

    but otherwise uses Pydantic's default behaviour.

    For now, ignore unknown fields. In the future, we could change this so that unknown
    config values cause a ValidationError, provided the error messages are meaningful to
    server operators.

    Subclassing in this way is recommended by
    https://pydantic-docs.helpmanual.io/usage/model_config/#change-behaviour-globally
    """

    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)


class InstanceTcpLocationConfig(ConfigModel):
    """The host and port to talk to an instance via HTTP replication."""

    host: str
    port: int
    tls: bool = False

    def scheme(self) -> str:
        """Hardcode a retrievable scheme based on self.tls"""
        return "https" if self.tls else "http"

    def netloc(self) -> str:
        """Nicely format the network location data"""
        return f"{self.host}:{self.port}"


class InstanceUnixLocationConfig(ConfigModel):
    """The socket file to talk to an instance via HTTP replication."""

    path: str

    def scheme(self) -> str:
        """Hardcode a retrievable scheme"""
        return "unix"

    def netloc(self) -> str:
        """Nicely format the address location data"""
        return f"{self.path}"


InstanceLocationConfig = Union[InstanceTcpLocationConfig, InstanceUnixLocationConfig]


@attr.s
class WriterLocations:
    """Specifies the instances that write various streams.

    Attributes:
        events: The instances that write to the event and backfill streams.
        typing: The instances that write to the typing stream. Currently
            can only be a single instance.
        to_device: The instances that write to the to_device stream. Currently
            can only be a single instance.
        account_data: The instances that write to the account data streams. Currently
            can only be a single instance.
        receipts: The instances that write to the receipts stream. Currently
            can only be a single instance.
        presence: The instances that write to the presence stream. Currently
            can only be a single instance.
    """

    events: list[str] = attr.ib(
        default=["master"],
        converter=_instance_to_list_converter,
    )
    typing: list[str] = attr.ib(
        default=["master"],
        converter=_instance_to_list_converter,
    )
    to_device: list[str] = attr.ib(
        default=["master"],
        converter=_instance_to_list_converter,
    )
    account_data: list[str] = attr.ib(
        default=["master"],
        converter=_instance_to_list_converter,
    )
    receipts: list[str] = attr.ib(
        default=["master"],
        converter=_instance_to_list_converter,
    )
    presence: list[str] = attr.ib(
        default=["master"],
        converter=_instance_to_list_converter,
    )


@attr.s(auto_attribs=True)
class OutboundFederationRestrictedTo:
    """Whether we limit outbound federation to a certain set of instances.

    Attributes:
        instances: optional list of instances that can make outbound federation
            requests. If None then all instances can make federation requests.
        locations: list of instance locations to connect to proxy via.
    """

    instances: Optional[list[str]]
    locations: list[InstanceLocationConfig] = attr.Factory(list)

    def __contains__(self, instance: str) -> bool:
        # It feels a bit dirty to return `True` if `instances` is `None`, but it makes
        # sense in downstream usage in the sense that if
        # `outbound_federation_restricted_to` is not configured, then any instance can
        # talk to federation (no restrictions so always return `True`).
        return self.instances is None or instance in self.instances


class WorkerConfig(Config):
    """The workers are processes run separately to the main relapse process.
    They have their own pid_file and listener configuration. They use the
    replication_url to talk to the main relapse process."""

    section = "worker"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        self.worker_app = config.get("worker_app")

        # Canonicalise worker_app so that master always has None
        if self.worker_app == "relapse.app.homeserver":
            self.worker_app = None

        self.worker_listeners = [
            parse_listener_def(i, x)
            for i, x in enumerate(config.get("worker_listeners", []))
        ]
        self.worker_daemonize = bool(config.get("worker_daemonize"))
        self.worker_pid_file = config.get("worker_pid_file")

        worker_log_config = config.get("worker_log_config")
        if worker_log_config is not None and not isinstance(worker_log_config, str):
            raise ConfigError("worker_log_config must be a string")
        self.worker_log_config = worker_log_config

        # The port on the main relapse for TCP replication
        if "worker_replication_port" in config:
            raise ConfigError(DIRECT_TCP_ERROR, ("worker_replication_port",))

        # The shared secret used for authentication when connecting to the main relapse.
        self.worker_replication_secret = config.get("worker_replication_secret", None)

        self.worker_name = config.get("worker_name", self.worker_app)
        self.instance_name = self.worker_name or MAIN_PROCESS_INSTANCE_NAME

        # This option is really only here to support `--manhole` command line
        # argument.
        manhole = config.get("worker_manhole")
        if manhole:
            self.worker_listeners.append(
                TCPListenerConfig(
                    port=manhole,
                    bind_addresses=["127.0.0.1"],
                    type="manhole",
                )
            )

        federation_sender_instances = self._worker_names_performing_this_duty(
            config, "federation_sender_instances"
        )
        self.send_federation = self.instance_name in federation_sender_instances
        self.federation_shard_config = ShardedWorkerHandlingConfig(
            federation_sender_instances
        )

        # A map from instance name to host/port of their HTTP replication endpoint.
        # Check if the main process is declared. The main process itself doesn't need
        # this data as it would never have to talk to itself.
        instance_map: dict[str, Any] = config.get("instance_map", {})

        if self.instance_name is not MAIN_PROCESS_INSTANCE_NAME:
            # For now, accept 'main' in the instance_map, but the replication system
            # expects 'master', force that into being until it's changed later.
            if MAIN_PROCESS_INSTANCE_MAP_NAME in instance_map:
                instance_map[MAIN_PROCESS_INSTANCE_NAME] = instance_map[
                    MAIN_PROCESS_INSTANCE_MAP_NAME
                ]
                del instance_map[MAIN_PROCESS_INSTANCE_MAP_NAME]

            else:
                # If we've gotten here, it means that the main process is not on the
                # instance_map.
                raise ConfigError(
                    _MISSING_MAIN_PROCESS_INSTANCE_MAP_DATA
                    % MAIN_PROCESS_INSTANCE_MAP_NAME
                )

        # type-ignore: the expression `Union[A, B]` is not a Type[Union[A, B]] currently
        self.instance_map: dict[str, InstanceLocationConfig] = (
            parse_and_validate_mapping(
                instance_map,
                InstanceLocationConfig,  # type: ignore[arg-type]
            )
        )

        # Map from type of streams to source, c.f. WriterLocations.
        writers = config.get("stream_writers") or {}
        self.writers = WriterLocations(**writers)

        # Check that the configured writers for events and typing also appears in
        # `instance_map`.
        for stream in (
            "events",
            "typing",
            "to_device",
            "account_data",
            "receipts",
            "presence",
        ):
            instances = _instance_to_list_converter(getattr(self.writers, stream))
            for instance in instances:
                if instance != "master" and instance not in self.instance_map:
                    raise ConfigError(
                        "Instance %r is configured to write %s but does not appear in `instance_map` config."
                        % (instance, stream)
                    )

        if len(self.writers.typing) != 1:
            raise ConfigError(
                "Must only specify one instance to handle `typing` messages."
            )

        if len(self.writers.to_device) != 1:
            raise ConfigError(
                "Must only specify one instance to handle `to_device` messages."
            )

        if len(self.writers.account_data) != 1:
            raise ConfigError(
                "Must only specify one instance to handle `account_data` messages."
            )

        if len(self.writers.receipts) == 0:
            raise ConfigError(
                "Must specify at least one instance to handle `receipts` messages."
            )

        if len(self.writers.events) == 0:
            raise ConfigError("Must specify at least one instance to handle `events`.")

        if len(self.writers.presence) != 1:
            raise ConfigError(
                "Must only specify one instance to handle `presence` messages."
            )

        self.events_shard_config = RoutableShardedWorkerHandlingConfig(
            self.writers.events
        )

        # Handle sharded push
        pusher_instances = self._worker_names_performing_this_duty(
            config, "pusher_instances"
        )
        self.start_pushers = self.instance_name in pusher_instances
        self.pusher_shard_config = ShardedWorkerHandlingConfig(pusher_instances)

        # Whether this worker should run background tasks or not.
        #
        # As a note for developers, the background tasks guarded by this should
        # be able to run on only a single instance (meaning that they don't
        # depend on any in-memory state of a particular worker).
        #
        # No effort is made to ensure only a single instance of these tasks is
        # running.
        self.run_background_tasks = self._should_this_worker_perform_duty(
            config, "run_background_tasks_on"
        )

        self.should_notify_appservices = self._should_this_worker_perform_duty(
            config, "notify_appservices_from_worker"
        )

        self.should_update_user_directory = self._should_this_worker_perform_duty(
            config, "update_user_directory_from_worker"
        )

        outbound_federation_restricted_to = config.get(
            "outbound_federation_restricted_to", None
        )
        self.outbound_federation_restricted_to = OutboundFederationRestrictedTo(
            outbound_federation_restricted_to
        )
        if outbound_federation_restricted_to:
            if not self.worker_replication_secret:
                raise ConfigError(
                    "`worker_replication_secret` must be configured when using `outbound_federation_restricted_to`."
                )

            for instance in outbound_federation_restricted_to:
                if instance not in self.instance_map:
                    raise ConfigError(
                        "Instance %r is configured in 'outbound_federation_restricted_to' but does not appear in `instance_map` config."
                        % (instance,)
                    )
                self.outbound_federation_restricted_to.locations.append(
                    self.instance_map[instance]
                )

    def _should_this_worker_perform_duty(
        self, config: dict[str, Any], option_name: str
    ) -> bool:
        """
        Figures out whether this worker should perform a certain duty.

        Parameters:
            config: The config dictionary
            option_name: The name of the new option, whose value is the name of a
                designated worker to perform the duty.
                e.g. "notify_appservices_from_worker"
        """

        # The fallback behaviour is to run on the main process
        designated_worker = config.get(option_name, "master")
        return (
            designated_worker == "master" and self.worker_name is None
        ) or designated_worker == self.worker_name

    def _worker_names_performing_this_duty(
        self,
        config: dict[str, Any],
        instance_list_name: str,
    ) -> list[str]:
        """
        Retrieves the names of the workers handling a given duty from instance
        list name, defaults to master.

        Args:
            config: settings read from yaml.
            instance_list_name: the string name of the new instance_list. e.g.
                'pusher_instances'

        Returns:
            A list of worker instance names handling the given duty.
        """
        worker_instances = config.get(instance_list_name)
        if worker_instances is None:
            worker_instances = ["master"]
        return worker_instances

    def read_arguments(self, args: argparse.Namespace) -> None:
        # We support a bunch of command line arguments that override options in
        # the config. A lot of these options have a worker_* prefix when running
        # on workers so we also have to override them when command line options
        # are specified.

        if args.daemonize is not None:
            self.worker_daemonize = args.daemonize
        if args.manhole is not None:
            self.worker_manhole = args.worker_manhole
