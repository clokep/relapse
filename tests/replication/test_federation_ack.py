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

from unittest import mock

from twisted.test.proto_helpers import MemoryReactor

from relapse.app.generic_worker import GenericWorkerServer
from relapse.replication.tcp.commands import FederationAckCommand
from relapse.replication.tcp.protocol import IReplicationConnection
from relapse.replication.tcp.streams.federation import FederationStream
from relapse.server import HomeServer
from relapse.util import Clock

from tests.unittest import HomeserverTestCase


class FederationAckTestCase(HomeserverTestCase):
    def default_config(self) -> dict:
        config = super().default_config()
        config["worker_app"] = "relapse.app.generic_worker"
        config["worker_name"] = "federation_sender1"
        config["federation_sender_instances"] = ["federation_sender1"]
        config["instance_map"] = {"main": {"host": "127.0.0.1", "port": 0}}
        return config

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        return self.setup_test_homeserver(homeserver_to_use=GenericWorkerServer)

    def test_federation_ack_sent(self) -> None:
        """A FEDERATION_ACK should be sent back after each RDATA federation

        This test checks that the federation sender is correctly sending back
        FEDERATION_ACK messages. The test works by spinning up a federation_sender
        worker server, and then fishing out its ReplicationCommandHandler. We wire
        the RCH up to a mock connection (so that we can observe the command being sent)
        and then poke in an RDATA row.

        XXX: it might be nice to do this by pretending to be a relapse master worker
        (or a redis server), and having the worker connect to us via a mocked-up TCP
        transport, rather than assuming that the implementation has a
        ReplicationCommandHandler.
        """
        rch = self.hs.get_replication_command_handler()

        # wire up the ReplicationCommandHandler to a mock connection, which needs
        # to implement IReplicationConnection. (Note that Mock doesn't understand
        # interfaces, but casing an interface to a list gives the attributes.)
        mock_connection = mock.Mock(spec=list(IReplicationConnection))
        rch.new_connection(mock_connection)

        # tell it it received an RDATA row
        self.get_success(
            rch.on_rdata(
                "federation",
                "master",
                token=10,
                rows=[
                    FederationStream.FederationStreamRow(
                        type="x", data={"test": [1, 2, 3]}
                    )
                ],
            )
        )

        # now check that the FEDERATION_ACK was sent
        mock_connection.send_command.assert_called_once()
        cmd = mock_connection.send_command.call_args[0][0]
        assert isinstance(cmd, FederationAckCommand)
        self.assertEqual(cmd.token, 10)
