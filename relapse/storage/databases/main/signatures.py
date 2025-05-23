# Copyright 2014-2016 OpenMarket Ltd
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

from collections.abc import Collection, Mapping

from unpaddedbase64 import encode_base64

from relapse.crypto.event_signing import compute_event_reference_hash
from relapse.storage.databases.main.events_worker import (
    EventRedactBehaviour,
    EventsWorkerStore,
)
from relapse.util.caches.descriptors import cached, cachedList


class SignatureWorkerStore(EventsWorkerStore):
    @cached()
    def get_event_reference_hash(self, event_id: str) -> Mapping[str, bytes]:
        # This is a dummy function to allow get_event_reference_hashes
        # to use its cache
        raise NotImplementedError()

    @cachedList(
        cached_method_name="get_event_reference_hash", list_name="event_ids", num_args=1
    )
    async def get_event_reference_hashes(
        self, event_ids: Collection[str]
    ) -> Mapping[str, Mapping[str, bytes]]:
        """Get all hashes for given events.

        Args:
            event_ids: The event IDs to get hashes for.

        Returns:
             A mapping of event ID to a mapping of algorithm to hash.
             Returns an empty dict for a given event id if that event is unknown.
        """
        events = await self.get_events(
            event_ids,
            redact_behaviour=EventRedactBehaviour.as_is,
            allow_rejected=True,
        )

        hashes: dict[str, dict[str, bytes]] = {}
        for event_id in event_ids:
            event = events.get(event_id)
            if event is None:
                hashes[event_id] = {}
            else:
                ref_alg, ref_hash_bytes = compute_event_reference_hash(event)
                hashes[event_id] = {ref_alg: ref_hash_bytes}

        return hashes

    async def add_event_hashes(
        self, event_ids: Collection[str]
    ) -> list[tuple[str, dict[str, str]]]:
        """

        Args:
            event_ids: The event IDs

        Returns:
            A list of tuples of event ID and a mapping of algorithm to base-64 encoded hash.
        """
        hashes = await self.get_event_reference_hashes(event_ids)
        encoded_hashes = {
            e_id: {k: encode_base64(v) for k, v in h.items() if k == "sha256"}
            for e_id, h in hashes.items()
        }

        return list(encoded_hashes.items())


class SignatureStore(SignatureWorkerStore):
    """Persistence for event signatures and hashes"""
