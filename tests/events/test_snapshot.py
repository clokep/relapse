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

from twisted.test.proto_helpers import MemoryReactor

from relapse.events import EventBase
from relapse.events.snapshot import EventContext
from relapse.rest import admin
from relapse.rest.client import login, room
from relapse.server import HomeServer
from relapse.util import Clock

from tests import unittest
from tests.test_utils.event_injection import create_event


class TestEventContext(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main
        self._storage_controllers = hs.get_storage_controllers()

        self.user_id = self.register_user("u1", "pass")
        self.user_tok = self.login("u1", "pass")
        self.room_id = self.helper.create_room_as(tok=self.user_tok)

    def test_serialize_deserialize_msg(self) -> None:
        """Test that an EventContext for a message event is the same after
        serialize/deserialize.
        """

        event, context = self.get_success(
            create_event(
                self.hs,
                room_id=self.room_id,
                type="m.test",
                sender=self.user_id,
            )
        )

        self._check_serialize_deserialize(event, context)

    def test_serialize_deserialize_state_no_prev(self) -> None:
        """Test that an EventContext for a state event (with not previous entry)
        is the same after serialize/deserialize.
        """
        event, context = self.get_success(
            create_event(
                self.hs,
                room_id=self.room_id,
                type="m.test",
                sender=self.user_id,
                state_key="",
            )
        )

        self._check_serialize_deserialize(event, context)

    def test_serialize_deserialize_state_prev(self) -> None:
        """Test that an EventContext for a state event (which replaces a
        previous entry) is the same after serialize/deserialize.
        """
        event, context = self.get_success(
            create_event(
                self.hs,
                room_id=self.room_id,
                type="m.room.member",
                sender=self.user_id,
                state_key=self.user_id,
                content={"membership": "leave"},
            )
        )

        self._check_serialize_deserialize(event, context)

    def _check_serialize_deserialize(
        self, event: EventBase, context: EventContext
    ) -> None:
        serialized = self.get_success(context.serialize(event, self.store))

        d_context = EventContext.deserialize(self._storage_controllers, serialized)

        self.assertEqual(context.state_group, d_context.state_group)
        self.assertEqual(context.rejected, d_context.rejected)
        self.assertEqual(
            context.state_group_before_event, d_context.state_group_before_event
        )
        self.assertEqual(context.state_group_deltas, d_context.state_group_deltas)
        self.assertEqual(context.app_service, d_context.app_service)

        self.assertEqual(
            self.get_success(context.get_current_state_ids()),
            self.get_success(d_context.get_current_state_ids()),
        )
        self.assertEqual(
            self.get_success(context.get_prev_state_ids()),
            self.get_success(d_context.get_prev_state_ids()),
        )
