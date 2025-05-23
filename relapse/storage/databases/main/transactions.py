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

import logging
from collections.abc import Iterable, Mapping
from enum import Enum
from typing import TYPE_CHECKING, Optional, cast

import attr
from canonicaljson import encode_canonical_json

from relapse.api.constants import Direction
from relapse.metrics.background_process_metrics import wrap_as_background_process
from relapse.storage._base import db_to_json
from relapse.storage.database import (
    DatabasePool,
    LoggingDatabaseConnection,
    LoggingTransaction,
)
from relapse.storage.databases.main.cache import CacheInvalidationWorkerStore
from relapse.types import JsonDict, StrCollection
from relapse.util.caches.descriptors import cached, cachedList

if TYPE_CHECKING:
    from relapse.server import HomeServer

db_binary_type = memoryview

logger = logging.getLogger(__name__)


class DestinationSortOrder(Enum):
    """Enum to define the sorting method used when returning destinations."""

    DESTINATION = "destination"
    RETRY_LAST_TS = "retry_last_ts"
    RETTRY_INTERVAL = "retry_interval"
    FAILURE_TS = "failure_ts"
    LAST_SUCCESSFUL_STREAM_ORDERING = "last_successful_stream_ordering"


@attr.s(slots=True, frozen=True, auto_attribs=True)
class DestinationRetryTimings:
    """The current destination retry timing info for a remote server."""

    # The first time we tried and failed to reach the remote server, in ms.
    failure_ts: int

    # The last time we tried and failed to reach the remote server, in ms.
    retry_last_ts: int

    # How long since the last time we tried to reach the remote server before
    # trying again, in ms.
    retry_interval: int


class TransactionWorkerStore(CacheInvalidationWorkerStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

        if hs.config.worker.run_background_tasks:
            self._clock.looping_call(self._cleanup_transactions, 30 * 60 * 1000)

    @wrap_as_background_process("cleanup_transactions")
    async def _cleanup_transactions(self) -> None:
        now = self._clock.time_msec()
        month_ago = now - 30 * 24 * 60 * 60 * 1000

        def _cleanup_transactions_txn(txn: LoggingTransaction) -> None:
            txn.execute("DELETE FROM received_transactions WHERE ts < ?", (month_ago,))

        await self.db_pool.runInteraction(
            "_cleanup_transactions", _cleanup_transactions_txn
        )

    async def get_received_txn_response(
        self, transaction_id: str, origin: str
    ) -> Optional[tuple[int, JsonDict]]:
        """For an incoming transaction from a given origin, check if we have
        already responded to it. If so, return the response code and response
        body (as a dict).

        Args:
            transaction_id
            origin

        Returns:
            None if we have not previously responded to this transaction or a
            2-tuple of (int, dict)
        """

        return await self.db_pool.runInteraction(
            "get_received_txn_response",
            self._get_received_txn_response,
            transaction_id,
            origin,
        )

    def _get_received_txn_response(
        self, txn: LoggingTransaction, transaction_id: str, origin: str
    ) -> Optional[tuple[int, JsonDict]]:
        result = self.db_pool.simple_select_one_txn(
            txn,
            table="received_transactions",
            keyvalues={"transaction_id": transaction_id, "origin": origin},
            retcols=("response_code", "response_json"),
            allow_none=True,
        )

        # If the result exists and the response code is non-0.
        if result and result[0]:
            return result[0], db_to_json(result[1])

        else:
            return None

    async def set_received_txn_response(
        self, transaction_id: str, origin: str, code: int, response_dict: JsonDict
    ) -> None:
        """Persist the response we returned for an incoming transaction, and
        should return for subsequent transactions with the same transaction_id
        and origin.

        Args:
            transaction_id: The incoming transaction ID.
            origin: The origin server.
            code: The response code.
            response_dict: The response, to be encoded into JSON.
        """

        await self.db_pool.simple_upsert(
            table="received_transactions",
            keyvalues={
                "transaction_id": transaction_id,
                "origin": origin,
            },
            values={},
            insertion_values={
                "response_code": code,
                "response_json": db_binary_type(encode_canonical_json(response_dict)),
                "ts": self._clock.time_msec(),
            },
            desc="set_received_txn_response",
        )

    @cached(max_entries=10000)
    async def get_destination_retry_timings(
        self,
        destination: str,
    ) -> Optional[DestinationRetryTimings]:
        """Gets the current retry timings (if any) for a given destination.

        Args:
            destination (str)

        Returns:
            None if not retrying
            Otherwise a dict for the retry scheme
        """

        result = await self.db_pool.runInteraction(
            "get_destination_retry_timings",
            self._get_destination_retry_timings,
            destination,
        )

        return result

    def _get_destination_retry_timings(
        self, txn: LoggingTransaction, destination: str
    ) -> Optional[DestinationRetryTimings]:
        result = self.db_pool.simple_select_one_txn(
            txn,
            table="destinations",
            keyvalues={"destination": destination},
            retcols=("failure_ts", "retry_last_ts", "retry_interval"),
            allow_none=True,
        )

        # check we have a row and retry_last_ts is not null or zero
        # (retry_last_ts can't be negative)
        if result and result[1]:
            return DestinationRetryTimings(
                failure_ts=result[0], retry_last_ts=result[1], retry_interval=result[2]
            )
        else:
            return None

    @cachedList(
        cached_method_name="get_destination_retry_timings", list_name="destinations"
    )
    async def get_destination_retry_timings_batch(
        self, destinations: StrCollection
    ) -> Mapping[str, Optional[DestinationRetryTimings]]:
        rows = cast(
            list[tuple[str, Optional[int], Optional[int], Optional[int]]],
            await self.db_pool.simple_select_many_batch(
                table="destinations",
                iterable=destinations,
                column="destination",
                retcols=(
                    "destination",
                    "failure_ts",
                    "retry_last_ts",
                    "retry_interval",
                ),
                desc="get_destination_retry_timings_batch",
            ),
        )

        return {
            destination: DestinationRetryTimings(
                failure_ts, retry_last_ts, retry_interval
            )
            for destination, failure_ts, retry_last_ts, retry_interval in rows
            if retry_last_ts and failure_ts and retry_interval
        }

    async def set_destination_retry_timings(
        self,
        destination: str,
        failure_ts: Optional[int],
        retry_last_ts: int,
        retry_interval: int,
    ) -> None:
        """Sets the current retry timings for a given destination.
        Both timings should be zero if retrying is no longer occurring.

        Args:
            destination
            failure_ts: when the server started failing (ms since epoch)
            retry_last_ts: time of last retry attempt in unix epoch ms
            retry_interval: how long until next retry in ms
        """

        await self.db_pool.runInteraction(
            "set_destination_retry_timings",
            self._set_destination_retry_timings_txn,
            destination,
            failure_ts,
            retry_last_ts,
            retry_interval,
            db_autocommit=True,  # Safe as it's a single upsert
        )

    def _set_destination_retry_timings_txn(
        self,
        txn: LoggingTransaction,
        destination: str,
        failure_ts: Optional[int],
        retry_last_ts: int,
        retry_interval: int,
    ) -> None:
        # Upsert retry time interval if retry_interval is zero (i.e. we're
        # resetting it) or greater than the existing retry interval.
        #
        # WARNING: This is executed in autocommit, so we shouldn't add any more
        # SQL calls in here (without being very careful).
        sql = """
            INSERT INTO destinations (
                destination, failure_ts, retry_last_ts, retry_interval
            )
                VALUES (?, ?, ?, ?)
            ON CONFLICT (destination) DO UPDATE SET
                    failure_ts = EXCLUDED.failure_ts,
                    retry_last_ts = EXCLUDED.retry_last_ts,
                    retry_interval = EXCLUDED.retry_interval
                WHERE
                    EXCLUDED.retry_interval = 0
                    OR EXCLUDED.retry_last_ts = 0
                    OR destinations.retry_interval IS NULL
                    OR destinations.retry_interval < EXCLUDED.retry_interval
                    OR destinations.retry_last_ts < EXCLUDED.retry_last_ts
        """

        txn.execute(sql, (destination, failure_ts, retry_last_ts, retry_interval))

        self._invalidate_cache_and_stream(
            txn, self.get_destination_retry_timings, (destination,)
        )

    async def store_destination_rooms_entries(
        self,
        destinations: Iterable[str],
        room_id: str,
        stream_ordering: int,
    ) -> None:
        """
        Updates or creates `destination_rooms` entries in batch for a single event.

        Args:
            destinations: list of destinations
            room_id: the room_id of the event
            stream_ordering: the stream_ordering of the event
        """

        await self.db_pool.simple_upsert_many(
            table="destinations",
            key_names=("destination",),
            key_values=[(d,) for d in destinations],
            value_names=[],
            value_values=[],
            desc="store_destination_rooms_entries_dests",
        )

        rows = [(destination, room_id) for destination in destinations]
        await self.db_pool.simple_upsert_many(
            table="destination_rooms",
            key_names=("destination", "room_id"),
            key_values=rows,
            value_names=["stream_ordering"],
            value_values=[(stream_ordering,)] * len(rows),
            desc="store_destination_rooms_entries_rooms",
        )

    async def get_destination_last_successful_stream_ordering(
        self, destination: str
    ) -> Optional[int]:
        """
        Gets the stream ordering of the PDU most-recently successfully sent
        to the specified destination, or None if this information has not been
        tracked yet.

        Args:
            destination: the destination to query
        """
        return await self.db_pool.simple_select_one_onecol(
            "destinations",
            {"destination": destination},
            "last_successful_stream_ordering",
            allow_none=True,
            desc="get_last_successful_stream_ordering",
        )

    async def set_destination_last_successful_stream_ordering(
        self, destination: str, last_successful_stream_ordering: int
    ) -> None:
        """
        Marks that we have successfully sent the PDUs up to and including the
        one specified.

        Args:
            destination: the destination we have successfully sent to
            last_successful_stream_ordering: the stream_ordering of the most
                recent successfully-sent PDU
        """
        await self.db_pool.simple_upsert(
            "destinations",
            keyvalues={"destination": destination},
            values={"last_successful_stream_ordering": last_successful_stream_ordering},
            desc="set_last_successful_stream_ordering",
        )

    async def get_catch_up_room_event_ids(
        self,
        destination: str,
        last_successful_stream_ordering: int,
    ) -> list[str]:
        """
        Returns at most 50 event IDs and their corresponding stream_orderings
        that correspond to the oldest events that have not yet been sent to
        the destination.

        Args:
            destination: the destination in question
            last_successful_stream_ordering: the stream_ordering of the
                most-recently successfully-transmitted event to the destination

        Returns:
            list of event_ids
        """
        return await self.db_pool.runInteraction(
            "get_catch_up_room_event_ids",
            self._get_catch_up_room_event_ids_txn,
            destination,
            last_successful_stream_ordering,
        )

    @staticmethod
    def _get_catch_up_room_event_ids_txn(
        txn: LoggingTransaction,
        destination: str,
        last_successful_stream_ordering: int,
    ) -> list[str]:
        q = """
                SELECT event_id FROM destination_rooms
                 JOIN events USING (stream_ordering)
                WHERE destination = ?
                  AND stream_ordering > ?
                ORDER BY stream_ordering
                LIMIT 50
            """
        txn.execute(
            q,
            (destination, last_successful_stream_ordering),
        )
        event_ids = [row[0] for row in txn]
        return event_ids

    async def get_catch_up_outstanding_destinations(
        self, after_destination: Optional[str]
    ) -> list[str]:
        """
        Gets at most 25 destinations which have outstanding PDUs to be caught up,
        and are not being backed off from
        Args:
            after_destination:
                If provided, all destinations must be lexicographically greater
                than this one.

        Returns:
            list of up to 25 destinations with outstanding catch-up.
                These are the lexicographically first destinations which are
                lexicographically greater than after_destination (if provided).
        """
        time = self.hs.get_clock().time_msec()

        return await self.db_pool.runInteraction(
            "get_catch_up_outstanding_destinations",
            self._get_catch_up_outstanding_destinations_txn,
            time,
            after_destination,
        )

    @staticmethod
    def _get_catch_up_outstanding_destinations_txn(
        txn: LoggingTransaction, now_time_ms: int, after_destination: Optional[str]
    ) -> list[str]:
        q = """
            SELECT DISTINCT destination FROM destinations
            INNER JOIN destination_rooms USING (destination)
                WHERE
                    stream_ordering > last_successful_stream_ordering
                    AND destination > ?
                    AND (
                        retry_last_ts IS NULL OR
                        retry_last_ts + retry_interval < ?
                    )
                    ORDER BY destination
                    LIMIT 25
        """
        txn.execute(
            q,
            (
                # everything is lexicographically greater than "" so this gives
                # us the first batch of up to 25.
                after_destination or "",
                now_time_ms,
            ),
        )

        destinations = [row[0] for row in txn]
        return destinations

    async def get_destinations_paginate(
        self,
        start: int,
        limit: int,
        destination: Optional[str] = None,
        order_by: str = DestinationSortOrder.DESTINATION.value,
        direction: Direction = Direction.FORWARDS,
    ) -> tuple[
        list[tuple[str, Optional[int], Optional[int], Optional[int], Optional[int]]],
        int,
    ]:
        """Function to retrieve a paginated list of destinations.
        This will return a json list of destinations and the
        total number of destinations matching the filter criteria.

        Args:
            start: start number to begin the query from
            limit: number of rows to retrieve
            destination: search string in destination
            order_by: the sort order of the returned list
            direction: sort ascending or descending
        Returns:
            A tuple of a list of tuples of destination information:
                * destination
                * retry_last_ts
                * retry_interval
                * failure_ts
                * last_successful_stream_ordering
            and a count of total destinations.
        """

        def get_destinations_paginate_txn(
            txn: LoggingTransaction,
        ) -> tuple[
            list[
                tuple[str, Optional[int], Optional[int], Optional[int], Optional[int]]
            ],
            int,
        ]:
            order_by_column = DestinationSortOrder(order_by).value

            if direction == Direction.BACKWARDS:
                order = "DESC"
            else:
                order = "ASC"

            args: list[object] = []
            where_statement = ""
            if destination:
                args.extend(["%" + destination.lower() + "%"])
                where_statement = "WHERE LOWER(destination) LIKE ?"

            sql_base = f"FROM destinations {where_statement} "
            sql = f"SELECT COUNT(*) as total_destinations {sql_base}"
            txn.execute(sql, args)
            count = cast(tuple[int], txn.fetchone())[0]

            sql = f"""
                SELECT destination, retry_last_ts, retry_interval, failure_ts,
                last_successful_stream_ordering
                {sql_base}
                ORDER BY {order_by_column} {order}, destination ASC
                LIMIT ? OFFSET ?
            """
            txn.execute(sql, args + [limit, start])
            destinations = cast(
                list[
                    tuple[
                        str, Optional[int], Optional[int], Optional[int], Optional[int]
                    ]
                ],
                txn.fetchall(),
            )
            return destinations, count

        return await self.db_pool.runInteraction(
            "get_destinations_paginate_txn", get_destinations_paginate_txn
        )

    async def get_destination_rooms_paginate(
        self,
        destination: str,
        start: int,
        limit: int,
        direction: Direction = Direction.FORWARDS,
    ) -> tuple[list[tuple[str, int]], int]:
        """Function to retrieve a paginated list of destination's rooms.
        This will return a json list of rooms and the
        total number of rooms.

        Args:
            destination: the destination to query
            start: start number to begin the query from
            limit: number of rows to retrieve
            direction: sort ascending or descending by room_id
        Returns:
            A tuple of a list of room tuples and a count of total rooms.

            Each room tuple is room_id, stream_ordering.
        """

        def get_destination_rooms_paginate_txn(
            txn: LoggingTransaction,
        ) -> tuple[list[tuple[str, int]], int]:
            if direction == Direction.BACKWARDS:
                order = "DESC"
            else:
                order = "ASC"

            sql = """
                SELECT COUNT(*) as total_rooms
                FROM destination_rooms
                WHERE destination = ?
                """
            txn.execute(sql, [destination])
            count = cast(tuple[int], txn.fetchone())[0]

            rooms = cast(
                list[tuple[str, int]],
                self.db_pool.simple_select_list_paginate_txn(
                    txn=txn,
                    table="destination_rooms",
                    orderby="room_id",
                    start=start,
                    limit=limit,
                    retcols=("room_id", "stream_ordering"),
                    order_direction=order,
                ),
            )
            return rooms, count

        return await self.db_pool.runInteraction(
            "get_destination_rooms_paginate_txn", get_destination_rooms_paginate_txn
        )

    async def is_destination_known(self, destination: str) -> bool:
        """Check if a destination is known to the server."""
        result = await self.db_pool.simple_select_one_onecol(
            table="destinations",
            keyvalues={"destination": destination},
            retcol="1",
            allow_none=True,
            desc="is_destination_known",
        )
        return bool(result)
