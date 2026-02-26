# Copyright 2018-2019 New Vector Ltd
# Copyright 2019 The Matrix.org Foundation C.I.C.
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
import json

from twisted.internet.testing import MemoryReactor

from relapse.api.constants import EventContentFields, EventTypes
from relapse.rest import admin
from relapse.rest.client import devices, knock, login, room, sync
from relapse.server import HomeServer
from relapse.types import JsonDict
from relapse.util import Clock

from tests import unittest
from tests.rest.federation.test_knocking import (
    KnockingStrippedStateEventHelperMixin,
)
from tests.server import TimedOutException


class FilterTestCase(unittest.HomeserverTestCase):
    user_id = "@apple:test"
    servlets = [
        admin.register_servlets,
        room.register_servlets,
        login.register_servlets,
        sync.register_servlets,
    ]

    def test_sync_argless(self) -> None:
        channel = self.make_request("GET", "/sync")

        self.assertEqual(channel.code, 200)
        self.assertIn("next_batch", channel.json_body)


class SyncFilterTestCase(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        room.register_servlets,
        login.register_servlets,
        sync.register_servlets,
    ]

    def test_sync_filter_labels(self) -> None:
        """Test that we can filter by a label."""
        sync_filter = json.dumps(
            {
                "room": {
                    "timeline": {
                        "types": [EventTypes.Message],
                        "org.matrix.labels": ["#fun"],
                    }
                }
            }
        )

        events = self._test_sync_filter_labels(sync_filter)

        self.assertEqual(len(events), 2, [event["content"] for event in events])
        self.assertEqual(events[0]["content"]["body"], "with right label", events[0])
        self.assertEqual(events[1]["content"]["body"], "with right label", events[1])

    def test_sync_filter_not_labels(self) -> None:
        """Test that we can filter by the absence of a label."""
        sync_filter = json.dumps(
            {
                "room": {
                    "timeline": {
                        "types": [EventTypes.Message],
                        "org.matrix.not_labels": ["#fun"],
                    }
                }
            }
        )

        events = self._test_sync_filter_labels(sync_filter)

        self.assertEqual(len(events), 3, [event["content"] for event in events])
        self.assertEqual(events[0]["content"]["body"], "without label", events[0])
        self.assertEqual(events[1]["content"]["body"], "with wrong label", events[1])
        self.assertEqual(
            events[2]["content"]["body"], "with two wrong labels", events[2]
        )

    def test_sync_filter_labels_not_labels(self) -> None:
        """Test that we can filter by both a label and the absence of another label."""
        sync_filter = json.dumps(
            {
                "room": {
                    "timeline": {
                        "types": [EventTypes.Message],
                        "org.matrix.labels": ["#work"],
                        "org.matrix.not_labels": ["#notfun"],
                    }
                }
            }
        )

        events = self._test_sync_filter_labels(sync_filter)

        self.assertEqual(len(events), 1, [event["content"] for event in events])
        self.assertEqual(events[0]["content"]["body"], "with wrong label", events[0])

    def _test_sync_filter_labels(self, sync_filter: str) -> list[JsonDict]:
        user_id = self.register_user("kermit", "test")
        tok = self.login("kermit", "test")

        room_id = self.helper.create_room_as(user_id, tok=tok)

        self.helper.send_event(
            room_id=room_id,
            type=EventTypes.Message,
            content={
                "msgtype": "m.text",
                "body": "with right label",
                EventContentFields.LABELS: ["#fun"],
            },
            tok=tok,
        )

        self.helper.send_event(
            room_id=room_id,
            type=EventTypes.Message,
            content={"msgtype": "m.text", "body": "without label"},
            tok=tok,
        )

        self.helper.send_event(
            room_id=room_id,
            type=EventTypes.Message,
            content={
                "msgtype": "m.text",
                "body": "with wrong label",
                EventContentFields.LABELS: ["#work"],
            },
            tok=tok,
        )

        self.helper.send_event(
            room_id=room_id,
            type=EventTypes.Message,
            content={
                "msgtype": "m.text",
                "body": "with two wrong labels",
                EventContentFields.LABELS: ["#work", "#notfun"],
            },
            tok=tok,
        )

        self.helper.send_event(
            room_id=room_id,
            type=EventTypes.Message,
            content={
                "msgtype": "m.text",
                "body": "with right label",
                EventContentFields.LABELS: ["#fun"],
            },
            tok=tok,
        )

        channel = self.make_request(
            "GET", f"/sync?filter={sync_filter}", access_token=tok
        )
        self.assertEqual(channel.code, 200, channel.result)

        return channel.json_body["rooms"]["join"][room_id]["timeline"]["events"]


class SyncTypingTests(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        room.register_servlets,
        login.register_servlets,
        sync.register_servlets,
    ]
    user_id = True
    hijack_auth = False

    def test_sync_backwards_typing(self) -> None:
        """
        If the typing serial goes backwards and the typing handler is then reset
        (such as when the master restarts and sets the typing serial to 0), we
        do not incorrectly return typing information that had a serial greater
        than the now-reset serial.
        """
        typing_url = "/rooms/%s/typing/%s?access_token=%s"
        sync_url = "/sync?timeout=3000000&access_token=%s&since=%s"

        # Register the user who gets notified
        user_id = self.register_user("user", "pass")
        access_token = self.login("user", "pass")

        # Register the user who sends the message
        other_user_id = self.register_user("otheruser", "pass")
        other_access_token = self.login("otheruser", "pass")

        # Create a room
        room = self.helper.create_room_as(user_id, tok=access_token)

        # Invite the other person
        self.helper.invite(room=room, src=user_id, tok=access_token, targ=other_user_id)

        # The other user joins
        self.helper.join(room=room, user=other_user_id, tok=other_access_token)

        # The other user sends some messages
        self.helper.send(room, body="Hi!", tok=other_access_token)
        self.helper.send(room, body="There!", tok=other_access_token)

        # Start typing.
        channel = self.make_request(
            "PUT",
            typing_url % (room, other_user_id, other_access_token),
            b'{"typing": true, "timeout": 30000}',
        )
        self.assertEqual(200, channel.code)

        channel = self.make_request("GET", f"/sync?access_token={access_token}")
        self.assertEqual(200, channel.code)
        next_batch = channel.json_body["next_batch"]

        # Stop typing.
        channel = self.make_request(
            "PUT",
            typing_url % (room, other_user_id, other_access_token),
            b'{"typing": false}',
        )
        self.assertEqual(200, channel.code)

        # Start typing.
        channel = self.make_request(
            "PUT",
            typing_url % (room, other_user_id, other_access_token),
            b'{"typing": true, "timeout": 30000}',
        )
        self.assertEqual(200, channel.code)

        # Should return immediately
        channel = self.make_request("GET", sync_url % (access_token, next_batch))
        self.assertEqual(200, channel.code)
        next_batch = channel.json_body["next_batch"]

        # Reset typing serial back to 0, as if the master had.
        typing = self.hs.get_typing_handler()
        typing._latest_room_serial = 0

        # Since it checks the state token, we need some state to update to
        # invalidate the stream token.
        self.helper.send(room, body="There!", tok=other_access_token)

        channel = self.make_request("GET", sync_url % (access_token, next_batch))
        self.assertEqual(200, channel.code)
        next_batch = channel.json_body["next_batch"]

        # This should time out! But it does not, because our stream token is
        # ahead, and therefore it's saying the typing (that we've actually
        # already seen) is new, since it's got a token above our new, now-reset
        # stream token.
        channel = self.make_request("GET", sync_url % (access_token, next_batch))
        self.assertEqual(200, channel.code)
        next_batch = channel.json_body["next_batch"]

        # Clear the typing information, so that it doesn't think everything is
        # in the future.
        typing._reset()

        # Now it SHOULD fail as it never completes!
        with self.assertRaises(TimedOutException):
            self.make_request("GET", sync_url % (access_token, next_batch))


class SyncKnockTestCase(KnockingStrippedStateEventHelperMixin):
    servlets = [
        admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
        sync.register_servlets,
        knock.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main
        self.url = "/sync?since=%s"
        self.next_batch = "s0"

        # Register the first user (used to create the room to knock on).
        self.user_id = self.register_user("kermit", "monkey")
        self.tok = self.login("kermit", "monkey")

        # Create the room we'll knock on.
        self.room_id = self.helper.create_room_as(
            self.user_id,
            is_public=False,
            room_version="7",
            tok=self.tok,
        )

        # Register the second user (used to knock on the room).
        self.knocker = self.register_user("knocker", "monkey")
        self.knocker_tok = self.login("knocker", "monkey")

        # Perform an initial sync for the knocking user.
        channel = self.make_request(
            "GET",
            self.url % self.next_batch,
            access_token=self.tok,
        )
        self.assertEqual(channel.code, 200, channel.json_body)

        # Store the next batch for the next request.
        self.next_batch = channel.json_body["next_batch"]

        # Set up some room state to test with.
        self.expected_room_state = self.send_example_state_events_to_room(
            hs, self.room_id, self.user_id
        )

    def test_knock_room_state(self) -> None:
        """Tests that /sync returns state from a room after knocking on it."""
        # Knock on a room
        channel = self.make_request(
            "POST",
            f"/_matrix/client/r0/knock/{self.room_id}",
            b"{}",
            self.knocker_tok,
        )
        self.assertEqual(200, channel.code, channel.result)

        # We expect to see the knock event in the stripped room state later
        self.expected_room_state[EventTypes.Member] = {
            "content": {"membership": "knock", "displayname": "knocker"},
            "state_key": "@knocker:test",
        }

        # Check that /sync includes stripped state from the room
        channel = self.make_request(
            "GET",
            self.url % self.next_batch,
            access_token=self.knocker_tok,
        )
        self.assertEqual(channel.code, 200, channel.json_body)

        # Extract the stripped room state events from /sync
        knock_entry = channel.json_body["rooms"]["knock"]
        room_state_events = knock_entry[self.room_id]["knock_state"]["events"]

        # Validate that the knock membership event came last
        self.assertEqual(room_state_events[-1]["type"], EventTypes.Member)

        # Validate the stripped room state events
        self.check_knock_room_state_against_room_state(
            room_state_events, self.expected_room_state
        )


class SyncCacheTestCase(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        login.register_servlets,
        sync.register_servlets,
    ]

    def test_noop_sync_does_not_tightloop(self) -> None:
        """If the sync times out, we shouldn't cache the result

        Essentially a regression test for https://github.com/matrix-org/synapse/issues/8518.
        """
        self.user_id = self.register_user("kermit", "monkey")
        self.tok = self.login("kermit", "monkey")

        # we should immediately get an initial sync response
        channel = self.make_request("GET", "/sync", access_token=self.tok)
        self.assertEqual(channel.code, 200, channel.json_body)

        # now, make an incremental sync request, with a timeout
        next_batch = channel.json_body["next_batch"]
        channel = self.make_request(
            "GET",
            f"/sync?since={next_batch}&timeout=10000",
            access_token=self.tok,
            await_result=False,
        )
        # that should block for 10 seconds
        with self.assertRaises(TimedOutException):
            channel.await_result(timeout_ms=9900)
        channel.await_result(timeout_ms=200)
        self.assertEqual(channel.code, 200, channel.json_body)

        # we expect the next_batch in the result to be the same as before
        self.assertEqual(channel.json_body["next_batch"], next_batch)

        # another incremental sync should also block.
        channel = self.make_request(
            "GET",
            f"/sync?since={next_batch}&timeout=10000",
            access_token=self.tok,
            await_result=False,
        )
        # that should block for 10 seconds
        with self.assertRaises(TimedOutException):
            channel.await_result(timeout_ms=9900)
        channel.await_result(timeout_ms=200)
        self.assertEqual(channel.code, 200, channel.json_body)


class DeviceListSyncTestCase(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        login.register_servlets,
        sync.register_servlets,
        devices.register_servlets,
    ]

    def test_user_with_no_rooms_receives_self_device_list_updates(self) -> None:
        """Tests that a user with no rooms still receives their own device list updates"""
        device_id = "TESTDEVICE"

        # Register a user and login, creating a device
        self.user_id = self.register_user("kermit", "monkey")
        self.tok = self.login("kermit", "monkey", device_id=device_id)

        # Request an initial sync
        channel = self.make_request("GET", "/sync", access_token=self.tok)
        self.assertEqual(channel.code, 200, channel.json_body)
        next_batch = channel.json_body["next_batch"]

        # Now, make an incremental sync request.
        # It won't return until something has happened
        incremental_sync_channel = self.make_request(
            "GET",
            f"/sync?since={next_batch}&timeout=30000",
            access_token=self.tok,
            await_result=False,
        )

        # Change our device's display name
        channel = self.make_request(
            "PUT",
            f"devices/{device_id}",
            {
                "display_name": "freeze ray",
            },
            access_token=self.tok,
        )
        self.assertEqual(channel.code, 200, channel.json_body)

        # The sync should now have returned
        incremental_sync_channel.await_result(timeout_ms=20000)
        self.assertEqual(incremental_sync_channel.code, 200, channel.json_body)

        # We should have received notification that the (user's) device has changed
        device_list_changes = incremental_sync_channel.json_body.get(
            "device_lists", {}
        ).get("changed", [])

        self.assertIn(
            self.user_id, device_list_changes, incremental_sync_channel.json_body
        )


class ExcludeRoomTestCase(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        login.register_servlets,
        sync.register_servlets,
        room.register_servlets,
    ]

    def prepare(
        self, reactor: MemoryReactor, clock: Clock, homeserver: HomeServer
    ) -> None:
        self.user_id = self.register_user("user", "password")
        self.tok = self.login("user", "password")

        self.excluded_room_id = self.helper.create_room_as(self.user_id, tok=self.tok)
        self.included_room_id = self.helper.create_room_as(self.user_id, tok=self.tok)

        # We need to manually append the room ID, because we can't know the ID before
        # creating the room, and we can't set the config after starting the homeserver.
        self.hs.get_sync_handler().rooms_to_exclude_globally.append(
            self.excluded_room_id
        )

    def test_join_leave(self) -> None:
        """Tests that rooms are correctly excluded from the 'join' and 'leave' sections of
        sync responses.
        """
        channel = self.make_request("GET", "/sync", access_token=self.tok)
        self.assertEqual(channel.code, 200, channel.result)

        self.assertNotIn(self.excluded_room_id, channel.json_body["rooms"]["join"])
        self.assertIn(self.included_room_id, channel.json_body["rooms"]["join"])

        self.helper.leave(self.excluded_room_id, self.user_id, tok=self.tok)
        self.helper.leave(self.included_room_id, self.user_id, tok=self.tok)

        channel = self.make_request(
            "GET",
            "/sync?since=" + channel.json_body["next_batch"],
            access_token=self.tok,
        )
        self.assertEqual(channel.code, 200, channel.result)

        self.assertNotIn(self.excluded_room_id, channel.json_body["rooms"]["leave"])
        self.assertIn(self.included_room_id, channel.json_body["rooms"]["leave"])

    def test_invite(self) -> None:
        """Tests that rooms are correctly excluded from the 'invite' section of sync
        responses.
        """
        invitee = self.register_user("invitee", "password")
        invitee_tok = self.login("invitee", "password")

        self.helper.invite(self.excluded_room_id, self.user_id, invitee, tok=self.tok)
        self.helper.invite(self.included_room_id, self.user_id, invitee, tok=self.tok)

        channel = self.make_request("GET", "/sync", access_token=invitee_tok)
        self.assertEqual(channel.code, 200, channel.result)

        self.assertNotIn(self.excluded_room_id, channel.json_body["rooms"]["invite"])
        self.assertIn(self.included_room_id, channel.json_body["rooms"]["invite"])

    def test_incremental_sync(self) -> None:
        """Tests that activity in the room is properly filtered out of incremental
        syncs.
        """
        channel = self.make_request("GET", "/sync", access_token=self.tok)
        self.assertEqual(channel.code, 200, channel.result)
        next_batch = channel.json_body["next_batch"]

        self.helper.send(self.excluded_room_id, tok=self.tok)
        self.helper.send(self.included_room_id, tok=self.tok)

        channel = self.make_request(
            "GET",
            f"/sync?since={next_batch}",
            access_token=self.tok,
        )
        self.assertEqual(channel.code, 200, channel.result)

        self.assertNotIn(self.excluded_room_id, channel.json_body["rooms"]["join"])
        self.assertIn(self.included_room_id, channel.json_body["rooms"]["join"])
