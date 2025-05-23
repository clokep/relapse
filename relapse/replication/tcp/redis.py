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
from inspect import isawaitable
from typing import TYPE_CHECKING, Any, Generic, Optional, TypeVar, cast

import attr
from txredisapi import (
    ConnectionHandler,
    RedisFactory,
    SubscriberProtocol,
    UnixConnectionHandler,
)
from zope.interface import implementer

from twisted.internet.address import IPv4Address, IPv6Address
from twisted.internet.interfaces import IAddress, IConnector
from twisted.python.failure import Failure

from relapse.logging.context import PreserveLoggingContext, make_deferred_yieldable
from relapse.metrics.background_process_metrics import (
    BackgroundProcessLoggingContext,
    run_as_background_process,
    wrap_as_background_process,
)
from relapse.replication.tcp.commands import (
    Command,
    ReplicateCommand,
    parse_command_from_line,
)
from relapse.replication.tcp.context import ClientContextFactory
from relapse.replication.tcp.protocol import (
    IReplicationConnection,
    tcp_inbound_commands_counter,
    tcp_outbound_commands_counter,
)

if TYPE_CHECKING:
    from relapse.replication.tcp.handler import ReplicationCommandHandler
    from relapse.server import HomeServer

logger = logging.getLogger(__name__)

T = TypeVar("T")
V = TypeVar("V")


@attr.s
class ConstantProperty(Generic[T, V]):
    """A descriptor that returns the given constant, ignoring attempts to set
    it.
    """

    constant: V = attr.ib()

    def __get__(self, obj: Optional[T], objtype: Optional[type[T]] = None) -> V:
        return self.constant

    def __set__(self, obj: Optional[T], value: V) -> None:
        pass


@implementer(IReplicationConnection)
class RedisSubscriber(SubscriberProtocol):
    """Connection to redis subscribed to replication stream.

    This class fulfils two functions:

    (a) it implements the twisted Protocol API, where it handles the SUBSCRIBEd redis
    connection, parsing *incoming* messages into replication commands, and passing them
    to `ReplicationCommandHandler`

    (b) it implements the IReplicationConnection API, where it sends *outgoing* commands
    onto outbound_redis_connection.

    Due to the vagaries of `txredisapi` we don't want to have a custom
    constructor, so instead we expect the defined attributes below to be set
    immediately after initialisation.

    Attributes:
        relapse_handler: The command handler to handle incoming commands.
        relapse_stream_prefix: The *redis* stream name to subscribe to and publish
            from (not anything to do with Relapse replication streams).
        relapse_outbound_redis_connection: The connection to redis to use to send
            commands.
    """

    relapse_handler: "ReplicationCommandHandler"
    relapse_stream_prefix: str
    relapse_channel_names: list[str]
    relapse_outbound_redis_connection: ConnectionHandler

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)

        # a logcontext which we use for processing incoming commands. We declare it as a
        # background process so that the CPU stats get reported to prometheus.
        with PreserveLoggingContext():
            # thanks to `PreserveLoggingContext()`, the new logcontext is guaranteed to
            # capture the sentinel context as its containing context and won't prevent
            # GC of / unintentionally reactivate what would be the current context.
            self._logging_context = BackgroundProcessLoggingContext(
                "replication_command_handler"
            )

    def connectionMade(self) -> None:
        logger.info("Connected to redis")
        super().connectionMade()
        run_as_background_process("subscribe-replication", self._send_subscribe)

    async def _send_subscribe(self) -> None:
        # it's important to make sure that we only send the REPLICATE command once we
        # have successfully subscribed to the stream - otherwise we might miss the
        # POSITION response sent back by the other end.
        fully_qualified_stream_names = [
            f"{self.relapse_stream_prefix}/{stream_suffix}"
            for stream_suffix in self.relapse_channel_names
        ] + [self.relapse_stream_prefix]
        logger.info("Sending redis SUBSCRIBE for %r", fully_qualified_stream_names)
        await make_deferred_yieldable(self.subscribe(fully_qualified_stream_names))

        logger.info(
            "Successfully subscribed to redis stream, sending REPLICATE command"
        )
        self.relapse_handler.new_connection(self)
        await self._async_send_command(ReplicateCommand())
        logger.info("REPLICATE successfully sent")

        # We send out our positions when there is a new connection in case the
        # other side missed updates. We do this for Redis connections as the
        # otherside won't know we've connected and so won't issue a REPLICATE.
        self.relapse_handler.send_positions_to_connection()

    def messageReceived(self, pattern: str, channel: str, message: str) -> None:
        """Received a message from redis."""
        with PreserveLoggingContext(self._logging_context):
            self._parse_and_dispatch_message(message)

    def _parse_and_dispatch_message(self, message: str) -> None:
        if message.strip() == "":
            # Ignore blank lines
            return

        try:
            cmd = parse_command_from_line(message)
        except Exception:
            logger.exception(
                "Failed to parse replication line: %r",
                message,
            )
            return

        # We use "redis" as the name here as we don't have 1:1 connections to
        # remote instances.
        tcp_inbound_commands_counter.labels(cmd.NAME, "redis").inc()

        self.handle_command(cmd)

    def handle_command(self, cmd: Command) -> None:
        """Handle a command we have received over the replication stream.

        Delegates to `self.handler.on_<COMMAND>` (which can optionally return an
        Awaitable).

        Args:
            cmd: received command
        """

        cmd_func = getattr(self.relapse_handler, "on_%s" % (cmd.NAME,), None)
        if not cmd_func:
            logger.warning("Unhandled command: %r", cmd)
            return

        res = cmd_func(self, cmd)

        # the handler might be a coroutine: fire it off as a background process
        # if so.

        if isawaitable(res):
            run_as_background_process(
                "replication-" + cmd.get_logcontext_id(), lambda: res
            )

    def connectionLost(self, reason: Failure) -> None:  # type: ignore[override]
        logger.info("Lost connection to redis")
        super().connectionLost(reason)
        self.relapse_handler.lost_connection(self)

        # mark the logging context as finished by triggering `__exit__()`
        with PreserveLoggingContext():
            with self._logging_context:
                pass
            # the sentinel context is now active, which may not be correct.
            # PreserveLoggingContext() will restore the correct logging context.

    def send_command(self, cmd: Command) -> None:
        """Send a command if connection has been established.

        Args:
            cmd: The command to send
        """
        run_as_background_process(
            "send-cmd", self._async_send_command, cmd, bg_start_span=False
        )

    async def _async_send_command(self, cmd: Command) -> None:
        """Encode a replication command and send it over our outbound connection"""
        string = "%s %s" % (cmd.NAME, cmd.to_line())
        if "\n" in string:
            raise Exception("Unexpected newline in command: %r", string)

        encoded_string = string.encode("utf-8")

        # We use "redis" as the name here as we don't have 1:1 connections to
        # remote instances.
        tcp_outbound_commands_counter.labels(cmd.NAME, "redis").inc()

        channel_name = cmd.redis_channel_name(self.relapse_stream_prefix)

        await make_deferred_yieldable(
            self.relapse_outbound_redis_connection.publish(channel_name, encoded_string)
        )


class RelapseRedisFactory(RedisFactory):
    """A subclass of RedisFactory that periodically sends pings to ensure that
    we detect dead connections.
    """

    # We want to *always* retry connecting, txredisapi will stop if there is a
    # failure during certain operations, e.g. during AUTH.
    continueTrying = cast(bool, ConstantProperty(True))

    def __init__(
        self,
        hs: "HomeServer",
        uuid: str,
        dbid: Optional[int],
        poolsize: int,
        isLazy: bool = False,
        handler: type = ConnectionHandler,
        charset: str = "utf-8",
        password: Optional[str] = None,
        replyTimeout: int = 30,
        convertNumbers: Optional[int] = True,
    ):
        super().__init__(
            uuid=uuid,
            dbid=dbid,
            poolsize=poolsize,
            isLazy=isLazy,
            handler=handler,
            charset=charset,
            password=password,
            replyTimeout=replyTimeout,
            convertNumbers=convertNumbers,
        )

        hs.get_clock().looping_call(self._send_ping, 30 * 1000)

    @wrap_as_background_process("redis_ping")
    async def _send_ping(self) -> None:
        for connection in self.pool:
            try:
                await make_deferred_yieldable(connection.ping())
            except Exception:
                logger.warning("Failed to send ping to a redis connection")

    # ReconnectingClientFactory has some logging (if you enable `self.noisy`), but
    # it's rubbish. We add our own here.

    def startedConnecting(self, connector: IConnector) -> None:
        logger.info(
            "Connecting to redis server %s", format_address(connector.getDestination())
        )
        super().startedConnecting(connector)

    def clientConnectionFailed(self, connector: IConnector, reason: Failure) -> None:
        logger.info(
            "Connection to redis server %s failed: %s",
            format_address(connector.getDestination()),
            reason.value,
        )
        super().clientConnectionFailed(connector, reason)

    def clientConnectionLost(self, connector: IConnector, reason: Failure) -> None:
        logger.info(
            "Connection to redis server %s lost: %s",
            format_address(connector.getDestination()),
            reason.value,
        )
        super().clientConnectionLost(connector, reason)


def format_address(address: IAddress) -> str:
    if isinstance(address, (IPv4Address, IPv6Address)):
        return "%s:%i" % (address.host, address.port)
    return str(address)


class RedisDirectTcpReplicationClientFactory(RelapseRedisFactory):
    """This is a reconnecting factory that connects to redis and immediately
    subscribes to some streams.

    Args:
        hs
        outbound_redis_connection: A connection to redis that will be used to
            send outbound commands (this is separate to the redis connection
            used to subscribe).
        channel_names: A list of channel names to append to the base channel name
            to additionally subscribe to.
            e.g. if ['ABC', 'DEF'] is specified then we'll listen to:
            example.com; example.com/ABC; and example.com/DEF.
    """

    maxDelay = 5
    protocol = RedisSubscriber

    def __init__(
        self,
        hs: "HomeServer",
        outbound_redis_connection: ConnectionHandler,
        channel_names: list[str],
    ):
        super().__init__(
            hs,
            uuid="subscriber",
            dbid=None,
            poolsize=1,
            replyTimeout=30,
            password=hs.config.redis.redis_password,
        )

        self.relapse_handler = hs.get_replication_command_handler()
        self.relapse_stream_prefix = hs.hostname
        self.relapse_channel_names = channel_names

        self.relapse_outbound_redis_connection = outbound_redis_connection

    def buildProtocol(self, addr: IAddress) -> RedisSubscriber:
        p = super().buildProtocol(addr)
        p = cast(RedisSubscriber, p)

        # We do this here rather than add to the constructor of `RedisSubcriber`
        # as to do so would involve overriding `buildProtocol` entirely, however
        # the base method does some other things than just instantiating the
        # protocol.
        p.relapse_handler = self.relapse_handler
        p.relapse_outbound_redis_connection = self.relapse_outbound_redis_connection
        p.relapse_stream_prefix = self.relapse_stream_prefix
        p.relapse_channel_names = self.relapse_channel_names

        return p


def lazyConnection(
    hs: "HomeServer",
    host: str = "localhost",
    port: int = 6379,
    dbid: Optional[int] = None,
    reconnect: bool = True,
    password: Optional[str] = None,
    replyTimeout: int = 30,
) -> ConnectionHandler:
    """Creates a connection to Redis that is lazily set up and reconnects if the
    connections is lost.
    """

    uuid = "%s:%d" % (host, port)
    factory = RelapseRedisFactory(
        hs,
        uuid=uuid,
        dbid=dbid,
        poolsize=1,
        isLazy=True,
        handler=ConnectionHandler,
        password=password,
        replyTimeout=replyTimeout,
    )
    factory.continueTrying = reconnect

    reactor = hs.get_reactor()

    if hs.config.redis.redis_use_tls:
        ssl_context_factory = ClientContextFactory(hs.config.redis)
        reactor.connectSSL(
            host,
            port,
            factory,
            ssl_context_factory,
            timeout=30,
            bindAddress=None,
        )
    else:
        reactor.connectTCP(
            host,
            port,
            factory,
            timeout=30,
            bindAddress=None,
        )

    return factory.handler


def lazyUnixConnection(
    hs: "HomeServer",
    path: str = "/tmp/redis.sock",
    dbid: Optional[int] = None,
    reconnect: bool = True,
    password: Optional[str] = None,
    replyTimeout: int = 30,
) -> ConnectionHandler:
    """Creates a connection to Redis that is lazily set up and reconnects if the
    connection is lost.

    Returns:
        A subclass of ConnectionHandler, which is a UnixConnectionHandler in this case.
    """

    uuid = path

    factory = RelapseRedisFactory(
        hs,
        uuid=uuid,
        dbid=dbid,
        poolsize=1,
        isLazy=True,
        handler=UnixConnectionHandler,
        password=password,
        replyTimeout=replyTimeout,
    )
    factory.continueTrying = reconnect

    reactor = hs.get_reactor()

    reactor.connectUNIX(
        path,
        factory,
        timeout=30,
        checkPID=False,
    )

    return factory.handler
