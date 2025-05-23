# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
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
from collections.abc import Collection, Iterable, Mapping, Sequence
from typing import TYPE_CHECKING, Any, List, Optional, Tuple, Union, cast

from twisted.internet import defer

from relapse.api.errors import StoreError
from relapse.config.homeserver import ExperimentalConfig
from relapse.logging.context import make_deferred_yieldable, run_in_background
from relapse.relapse_rust.push import FilteredPushRules, PushRule, PushRules
from relapse.replication.tcp.streams import PushRulesStream
from relapse.storage._base import SQLBaseStore
from relapse.storage.database import (
    DatabasePool,
    LoggingDatabaseConnection,
    LoggingTransaction,
)
from relapse.storage.databases.main.appservice import ApplicationServiceWorkerStore
from relapse.storage.databases.main.events_worker import EventsWorkerStore
from relapse.storage.databases.main.pusher import PusherWorkerStore
from relapse.storage.databases.main.receipts import ReceiptsWorkerStore
from relapse.storage.databases.main.roommember import RoomMemberWorkerStore
from relapse.storage.engines import PostgresEngine, Sqlite3Engine
from relapse.storage.push_rule import InconsistentRuleException, RuleNotFoundException
from relapse.storage.util.id_generators import (
    AbstractStreamIdGenerator,
    IdGenerator,
    StreamIdGenerator,
)
from relapse.types import JsonDict
from relapse.util import json_encoder, unwrapFirstError
from relapse.util.async_helpers import gather_results
from relapse.util.caches.descriptors import cached, cachedList
from relapse.util.caches.stream_change_cache import StreamChangeCache

if TYPE_CHECKING:
    from relapse.server import HomeServer

logger = logging.getLogger(__name__)


def _load_rules(
    rawrules: list[tuple[str, int, str, str]],
    enabled_map: dict[str, bool],
    experimental_config: ExperimentalConfig,
) -> FilteredPushRules:
    """Take the DB rows returned from the DB and convert them into a full
    `FilteredPushRules` object.

    Args:
        rawrules: List of tuples of:
            * rule ID
            * Priority lass
            * Conditions (as serialized JSON)
            * Actions (as serialized JSON)
        enabled_map: A dictionary of rule ID to a boolean of whether the rule is
            enabled. This might not include all rule IDs from rawrules.
        experimental_config: The `experimental_features` section of the Relapse
            config. (Used to check if various features are enabled.)

    Returns:
        A new FilteredPushRules object.
    """

    ruleslist = [
        PushRule.from_db(
            rule_id=rawrule[0],
            priority_class=rawrule[1],
            conditions=rawrule[2],
            actions=rawrule[3],
        )
        for rawrule in rawrules
    ]

    push_rules = PushRules(ruleslist)

    filtered_rules = FilteredPushRules(
        push_rules,
        enabled_map,
        msc1767_enabled=experimental_config.msc1767_enabled,
        msc3664_enabled=experimental_config.msc3664_enabled,
        msc3381_polls_enabled=experimental_config.msc3381_polls_enabled,
        msc4028_push_encrypted_events=experimental_config.msc4028_push_encrypted_events,
    )

    return filtered_rules


class PushRulesWorkerStore(
    ApplicationServiceWorkerStore,
    PusherWorkerStore,
    RoomMemberWorkerStore,
    ReceiptsWorkerStore,
    EventsWorkerStore,
    SQLBaseStore,
):
    """This is an abstract base class where subclasses must implement
    `get_max_push_rules_stream_id` which can be called in the initializer.
    """

    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

        # In the worker store this is an ID tracker which we overwrite in the non-worker
        # class below that is used on the main process.
        self._push_rules_stream_id_gen = StreamIdGenerator(
            db_conn,
            hs.get_replication_notifier(),
            "push_rules_stream",
            "stream_id",
            is_writer=hs.config.worker.worker_app is None,
        )

        push_rules_prefill, push_rules_id = self.db_pool.get_cache_dict(
            db_conn,
            "push_rules_stream",
            entity_column="user_id",
            stream_column="stream_id",
            max_value=self.get_max_push_rules_stream_id(),
        )

        self.push_rules_stream_cache = StreamChangeCache(
            "PushRulesStreamChangeCache",
            push_rules_id,
            prefilled_cache=push_rules_prefill,
        )

    def get_max_push_rules_stream_id(self) -> int:
        """Get the position of the push rules stream.

        Returns:
            int
        """
        return self._push_rules_stream_id_gen.get_current_token()

    def process_replication_rows(
        self, stream_name: str, instance_name: str, token: int, rows: Iterable[Any]
    ) -> None:
        if stream_name == PushRulesStream.NAME:
            self._push_rules_stream_id_gen.advance(instance_name, token)
            for row in rows:
                self.get_push_rules_for_user.invalidate((row.user_id,))
                self.push_rules_stream_cache.entity_has_changed(row.user_id, token)
        return super().process_replication_rows(stream_name, instance_name, token, rows)

    def process_replication_position(
        self, stream_name: str, instance_name: str, token: int
    ) -> None:
        if stream_name == PushRulesStream.NAME:
            self._push_rules_stream_id_gen.advance(instance_name, token)
        super().process_replication_position(stream_name, instance_name, token)

    @cached(max_entries=5000)
    async def get_push_rules_for_user(self, user_id: str) -> FilteredPushRules:
        rows = cast(
            list[tuple[str, int, int, str, str]],
            await self.db_pool.simple_select_list(
                table="push_rules",
                keyvalues={"user_name": user_id},
                retcols=(
                    "rule_id",
                    "priority_class",
                    "priority",
                    "conditions",
                    "actions",
                ),
                desc="get_push_rules_for_user",
            ),
        )

        # Sort by highest priority_class, then highest priority.
        rows.sort(key=lambda row: (-int(row[1]), -int(row[2])))

        enabled_map = await self.get_push_rules_enabled_for_user(user_id)

        return _load_rules(
            [(row[0], row[1], row[3], row[4]) for row in rows],
            enabled_map,
            self.hs.config.experimental,
        )

    async def get_push_rules_enabled_for_user(self, user_id: str) -> dict[str, bool]:
        results = cast(
            list[tuple[str, Optional[Union[int, bool]]]],
            await self.db_pool.simple_select_list(
                table="push_rules_enable",
                keyvalues={"user_name": user_id},
                retcols=("rule_id", "enabled"),
                desc="get_push_rules_enabled_for_user",
            ),
        )
        return {r[0]: bool(r[1]) for r in results}

    async def have_push_rules_changed_for_user(
        self, user_id: str, last_id: int
    ) -> bool:
        if not self.push_rules_stream_cache.has_entity_changed(user_id, last_id):
            return False
        else:

            def have_push_rules_changed_txn(txn: LoggingTransaction) -> bool:
                sql = (
                    "SELECT COUNT(stream_id) FROM push_rules_stream"
                    " WHERE user_id = ? AND ? < stream_id"
                )
                txn.execute(sql, (user_id, last_id))
                (count,) = cast(tuple[int], txn.fetchone())
                return bool(count)

            return await self.db_pool.runInteraction(
                "have_push_rules_changed", have_push_rules_changed_txn
            )

    @cachedList(cached_method_name="get_push_rules_for_user", list_name="user_ids")
    async def bulk_get_push_rules(
        self, user_ids: Collection[str]
    ) -> Mapping[str, FilteredPushRules]:
        if not user_ids:
            return {}

        raw_rules: dict[str, list[tuple[str, int, str, str]]] = {
            user_id: [] for user_id in user_ids
        }

        # gatherResults loses all type information.
        rows, enabled_map_by_user = await make_deferred_yieldable(
            gather_results(
                (
                    cast(
                        "defer.Deferred[List[Tuple[str, str, int, int, str, str]]]",
                        run_in_background(
                            self.db_pool.simple_select_many_batch,
                            table="push_rules",
                            column="user_name",
                            iterable=user_ids,
                            retcols=(
                                "user_name",
                                "rule_id",
                                "priority_class",
                                "priority",
                                "conditions",
                                "actions",
                            ),
                            desc="bulk_get_push_rules",
                            batch_size=1000,
                        ),
                    ),
                    run_in_background(self.bulk_get_push_rules_enabled, user_ids),
                ),
                consumeErrors=True,
            ).addErrback(unwrapFirstError)
        )

        # Sort by highest priority_class, then highest priority.
        rows.sort(key=lambda row: (-int(row[2]), -int(row[3])))

        for user_name, rule_id, priority_class, _, conditions, actions in rows:
            raw_rules.setdefault(user_name, []).append(
                (rule_id, priority_class, conditions, actions)
            )

        results: dict[str, FilteredPushRules] = {}

        for user_id, rules in raw_rules.items():
            results[user_id] = _load_rules(
                rules, enabled_map_by_user.get(user_id, {}), self.hs.config.experimental
            )

        return results

    async def bulk_get_push_rules_enabled(
        self, user_ids: Collection[str]
    ) -> dict[str, dict[str, bool]]:
        if not user_ids:
            return {}

        results: dict[str, dict[str, bool]] = {user_id: {} for user_id in user_ids}

        rows = cast(
            list[tuple[str, str, Optional[int]]],
            await self.db_pool.simple_select_many_batch(
                table="push_rules_enable",
                column="user_name",
                iterable=user_ids,
                retcols=("user_name", "rule_id", "enabled"),
                desc="bulk_get_push_rules_enabled",
                batch_size=1000,
            ),
        )
        for user_name, rule_id, enabled in rows:
            results.setdefault(user_name, {})[rule_id] = bool(enabled)
        return results

    async def get_all_push_rule_updates(
        self, instance_name: str, last_id: int, current_id: int, limit: int
    ) -> tuple[list[tuple[int, tuple[str]]], int, bool]:
        """Get updates for push_rules replication stream.

        Args:
            instance_name: The writer we want to fetch updates from. Unused
                here since there is only ever one writer.
            last_id: The token to fetch updates from. Exclusive.
            current_id: The token to fetch updates up to. Inclusive.
            limit: The requested limit for the number of rows to return. The
                function may return more or fewer rows.

        Returns:
            A tuple consisting of: the updates, a token to use to fetch
            subsequent updates, and whether we returned fewer rows than exists
            between the requested tokens due to the limit.

            The token returned can be used in a subsequent call to this
            function to get further updatees.

            The updates are a list of 2-tuples of stream ID and the row data
        """

        if last_id == current_id:
            return [], current_id, False

        def get_all_push_rule_updates_txn(
            txn: LoggingTransaction,
        ) -> tuple[list[tuple[int, tuple[str]]], int, bool]:
            sql = """
                SELECT stream_id, user_id
                FROM push_rules_stream
                WHERE ? < stream_id AND stream_id <= ?
                ORDER BY stream_id ASC
                LIMIT ?
            """
            txn.execute(sql, (last_id, current_id, limit))
            updates = cast(
                list[tuple[int, tuple[str]]],
                [(stream_id, (user_id,)) for stream_id, user_id in txn],
            )

            limited = False
            upper_bound = current_id
            if len(updates) == limit:
                limited = True
                upper_bound = updates[-1][0]

            return updates, upper_bound, limited

        return await self.db_pool.runInteraction(
            "get_all_push_rule_updates", get_all_push_rule_updates_txn
        )


class PushRuleStore(PushRulesWorkerStore):
    # Because we have write access, this will be a StreamIdGenerator
    # (see PushRulesWorkerStore.__init__)
    _push_rules_stream_id_gen: AbstractStreamIdGenerator

    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

        self._push_rule_id_gen = IdGenerator(db_conn, "push_rules", "id")
        self._push_rules_enable_id_gen = IdGenerator(db_conn, "push_rules_enable", "id")

    async def add_push_rule(
        self,
        user_id: str,
        rule_id: str,
        priority_class: int,
        conditions: Sequence[Mapping[str, str]],
        actions: Sequence[Union[Mapping[str, Any], str]],
        before: Optional[str] = None,
        after: Optional[str] = None,
    ) -> None:
        conditions_json = json_encoder.encode(conditions)
        actions_json = json_encoder.encode(actions)
        async with self._push_rules_stream_id_gen.get_next() as stream_id:
            event_stream_ordering = self._stream_id_gen.get_current_token()

            if before or after:
                await self.db_pool.runInteraction(
                    "_add_push_rule_relative_txn",
                    self._add_push_rule_relative_txn,
                    stream_id,
                    event_stream_ordering,
                    user_id,
                    rule_id,
                    priority_class,
                    conditions_json,
                    actions_json,
                    before,
                    after,
                )
            else:
                await self.db_pool.runInteraction(
                    "_add_push_rule_highest_priority_txn",
                    self._add_push_rule_highest_priority_txn,
                    stream_id,
                    event_stream_ordering,
                    user_id,
                    rule_id,
                    priority_class,
                    conditions_json,
                    actions_json,
                )

    def _add_push_rule_relative_txn(
        self,
        txn: LoggingTransaction,
        stream_id: int,
        event_stream_ordering: int,
        user_id: str,
        rule_id: str,
        priority_class: int,
        conditions_json: str,
        actions_json: str,
        before: str,
        after: str,
    ) -> None:
        relative_to_rule = before or after

        sql = """
            SELECT priority, priority_class FROM push_rules
            WHERE user_name = ? AND rule_id = ?
        """

        if isinstance(self.database_engine, PostgresEngine):
            sql += " FOR UPDATE"
        else:
            # Annoyingly SQLite doesn't support row level locking, so lock the whole table
            self.database_engine.lock_table(txn, "push_rules")

        txn.execute(sql, (user_id, relative_to_rule))
        row = txn.fetchone()

        if row is None:
            raise RuleNotFoundException(
                "before/after rule not found: %s" % (relative_to_rule,)
            )

        base_rule_priority, base_priority_class = row

        if base_priority_class != priority_class:
            raise InconsistentRuleException(
                "Given priority class does not match class of relative rule"
            )

        if before:
            # Higher priority rules are executed first, So adding a rule before
            # a rule means giving it a higher priority than that rule.
            new_rule_priority = base_rule_priority + 1
        else:
            # We increment the priority of the existing rules to make space for
            # the new rule. Therefore if we want this rule to appear after
            # an existing rule we give it the priority of the existing rule,
            # and then increment the priority of the existing rule.
            new_rule_priority = base_rule_priority

        sql = (
            "UPDATE push_rules SET priority = priority + 1"
            " WHERE user_name = ? AND priority_class = ? AND priority >= ?"
        )

        txn.execute(sql, (user_id, priority_class, new_rule_priority))

        self._upsert_push_rule_txn(
            txn,
            stream_id,
            event_stream_ordering,
            user_id,
            rule_id,
            priority_class,
            new_rule_priority,
            conditions_json,
            actions_json,
        )

    def _add_push_rule_highest_priority_txn(
        self,
        txn: LoggingTransaction,
        stream_id: int,
        event_stream_ordering: int,
        user_id: str,
        rule_id: str,
        priority_class: int,
        conditions_json: str,
        actions_json: str,
    ) -> None:
        if isinstance(self.database_engine, PostgresEngine):
            # Postgres doesn't do FOR UPDATE on aggregate functions, so select the rows first
            # then re-select the count/max below.
            sql = """
                SELECT * FROM push_rules
                WHERE user_name = ? and priority_class = ?
                FOR UPDATE
            """
            txn.execute(sql, (user_id, priority_class))
        else:
            # Annoyingly SQLite doesn't support row level locking, so lock the whole table
            self.database_engine.lock_table(txn, "push_rules")

        # find the highest priority rule in that class
        sql = (
            "SELECT COUNT(*), MAX(priority) FROM push_rules"
            " WHERE user_name = ? and priority_class = ?"
        )
        txn.execute(sql, (user_id, priority_class))
        res = txn.fetchall()
        (how_many, highest_prio) = res[0]

        new_prio = 0
        if how_many > 0:
            new_prio = highest_prio + 1

        self._upsert_push_rule_txn(
            txn,
            stream_id,
            event_stream_ordering,
            user_id,
            rule_id,
            priority_class,
            new_prio,
            conditions_json,
            actions_json,
        )

    def _upsert_push_rule_txn(
        self,
        txn: LoggingTransaction,
        stream_id: int,
        event_stream_ordering: int,
        user_id: str,
        rule_id: str,
        priority_class: int,
        priority: int,
        conditions_json: str,
        actions_json: str,
        update_stream: bool = True,
    ) -> None:
        """Specialised version of simple_upsert_txn that picks a push_rule_id
        using the _push_rule_id_gen if it needs to insert the rule. It assumes
        that the "push_rules" table is locked"""

        sql = (
            "UPDATE push_rules"
            " SET priority_class = ?, priority = ?, conditions = ?, actions = ?"
            " WHERE user_name = ? AND rule_id = ?"
        )

        txn.execute(
            sql,
            (priority_class, priority, conditions_json, actions_json, user_id, rule_id),
        )

        if txn.rowcount == 0:
            # We didn't update a row with the given rule_id so insert one
            push_rule_id = self._push_rule_id_gen.get_next()

            self.db_pool.simple_insert_txn(
                txn,
                table="push_rules",
                values={
                    "id": push_rule_id,
                    "user_name": user_id,
                    "rule_id": rule_id,
                    "priority_class": priority_class,
                    "priority": priority,
                    "conditions": conditions_json,
                    "actions": actions_json,
                },
            )

        if update_stream:
            self._insert_push_rules_update_txn(
                txn,
                stream_id,
                event_stream_ordering,
                user_id,
                rule_id,
                op="ADD",
                data={
                    "priority_class": priority_class,
                    "priority": priority,
                    "conditions": conditions_json,
                    "actions": actions_json,
                },
            )

        # ensure we have a push_rules_enable row
        # enabledness defaults to true
        if isinstance(self.database_engine, PostgresEngine):
            sql = """
                INSERT INTO push_rules_enable (id, user_name, rule_id, enabled)
                VALUES (?, ?, ?, 1)
                ON CONFLICT DO NOTHING
            """
        elif isinstance(self.database_engine, Sqlite3Engine):
            sql = """
                INSERT OR IGNORE INTO push_rules_enable (id, user_name, rule_id, enabled)
                VALUES (?, ?, ?, 1)
            """
        else:
            raise RuntimeError("Unknown database engine")

        new_enable_id = self._push_rules_enable_id_gen.get_next()
        txn.execute(sql, (new_enable_id, user_id, rule_id))

    async def delete_push_rule(self, user_id: str, rule_id: str) -> None:
        """
        Delete a push rule. Args specify the row to be deleted and can be
        any of the columns in the push_rule table, but below are the
        standard ones

        Args:
            user_id: The matrix ID of the push rule owner
            rule_id: The rule_id of the rule to be deleted
        """

        def delete_push_rule_txn(
            txn: LoggingTransaction,
            stream_id: int,
            event_stream_ordering: int,
        ) -> None:
            # we don't use simple_delete_one_txn because that would fail if the
            # user did not have a push_rule_enable row.
            self.db_pool.simple_delete_txn(
                txn, "push_rules_enable", {"user_name": user_id, "rule_id": rule_id}
            )

            self.db_pool.simple_delete_one_txn(
                txn, "push_rules", {"user_name": user_id, "rule_id": rule_id}
            )

            self._insert_push_rules_update_txn(
                txn, stream_id, event_stream_ordering, user_id, rule_id, op="DELETE"
            )

        async with self._push_rules_stream_id_gen.get_next() as stream_id:
            event_stream_ordering = self._stream_id_gen.get_current_token()

            await self.db_pool.runInteraction(
                "delete_push_rule",
                delete_push_rule_txn,
                stream_id,
                event_stream_ordering,
            )

    async def set_push_rule_enabled(
        self, user_id: str, rule_id: str, enabled: bool, is_default_rule: bool
    ) -> None:
        """
        Sets the `enabled` state of a push rule.

        Args:
            user_id: the user ID of the user who wishes to enable/disable the rule
                e.g. '@tina:example.org'
            rule_id: the full rule ID of the rule to be enabled/disabled
                e.g. 'global/override/.m.rule.roomnotif'
                  or 'global/override/myCustomRule'
            enabled: True if the rule is to be enabled, False if it is to be
                disabled
            is_default_rule: True if and only if this is a server-default rule.
                This skips the check for existence (as only user-created rules
                are always stored in the database `push_rules` table).

        Raises:
            RuleNotFoundException if the rule does not exist.
        """
        async with self._push_rules_stream_id_gen.get_next() as stream_id:
            event_stream_ordering = self._stream_id_gen.get_current_token()
            await self.db_pool.runInteraction(
                "_set_push_rule_enabled_txn",
                self._set_push_rule_enabled_txn,
                stream_id,
                event_stream_ordering,
                user_id,
                rule_id,
                enabled,
                is_default_rule,
            )

    def _set_push_rule_enabled_txn(
        self,
        txn: LoggingTransaction,
        stream_id: int,
        event_stream_ordering: int,
        user_id: str,
        rule_id: str,
        enabled: bool,
        is_default_rule: bool,
    ) -> None:
        new_id = self._push_rules_enable_id_gen.get_next()

        if not is_default_rule:
            # first check it exists; we need to lock for key share so that a
            # transaction that deletes the push rule will conflict with this one.
            # We also need a push_rule_enable row to exist for every push_rules
            # row, otherwise it is possible to simultaneously delete a push rule
            # (that has no _enable row) and enable it, resulting in a dangling
            # _enable row. To solve this: we either need to use SERIALISABLE or
            # ensure we always have a push_rule_enable row for every push_rule
            # row. We chose the latter.
            for_key_share = "FOR KEY SHARE"
            if not isinstance(self.database_engine, PostgresEngine):
                # For key share is not applicable/available on SQLite
                for_key_share = ""
            sql = (
                """
                SELECT 1 FROM push_rules
                WHERE user_name = ? AND rule_id = ?
                %s
            """
                % for_key_share
            )
            txn.execute(sql, (user_id, rule_id))
            if txn.fetchone() is None:
                raise RuleNotFoundException("Push rule does not exist.")

        self.db_pool.simple_upsert_txn(
            txn,
            "push_rules_enable",
            {"user_name": user_id, "rule_id": rule_id},
            {"enabled": 1 if enabled else 0},
            {"id": new_id},
        )

        self._insert_push_rules_update_txn(
            txn,
            stream_id,
            event_stream_ordering,
            user_id,
            rule_id,
            op="ENABLE" if enabled else "DISABLE",
        )

    async def set_push_rule_actions(
        self,
        user_id: str,
        rule_id: str,
        actions: list[Union[dict, str]],
        is_default_rule: bool,
    ) -> None:
        """
        Sets the `actions` state of a push rule.

        Args:
            user_id: the user ID of the user who wishes to enable/disable the rule
                e.g. '@tina:example.org'
            rule_id: the full rule ID of the rule to be enabled/disabled
                e.g. 'global/override/.m.rule.roomnotif'
                  or 'global/override/myCustomRule'
            actions: A list of actions (each action being a dict or string),
                e.g. ["notify", {"set_tweak": "highlight", "value": false}]
            is_default_rule: True if and only if this is a server-default rule.
                This skips the check for existence (as only user-created rules
                are always stored in the database `push_rules` table).

        Raises:
            RuleNotFoundException if the rule does not exist.
        """
        actions_json = json_encoder.encode(actions)

        def set_push_rule_actions_txn(
            txn: LoggingTransaction,
            stream_id: int,
            event_stream_ordering: int,
        ) -> None:
            if is_default_rule:
                # Add a dummy rule to the rules table with the user specified
                # actions.
                priority_class = -1
                priority = 1
                self._upsert_push_rule_txn(
                    txn,
                    stream_id,
                    event_stream_ordering,
                    user_id,
                    rule_id,
                    priority_class,
                    priority,
                    "[]",
                    actions_json,
                    update_stream=False,
                )
            else:
                try:
                    self.db_pool.simple_update_one_txn(
                        txn,
                        "push_rules",
                        {"user_name": user_id, "rule_id": rule_id},
                        {"actions": actions_json},
                    )
                except StoreError as serr:
                    if serr.code == 404:
                        # this sets the NOT_FOUND error Code
                        raise RuleNotFoundException("Push rule does not exist")
                    else:
                        raise

            self._insert_push_rules_update_txn(
                txn,
                stream_id,
                event_stream_ordering,
                user_id,
                rule_id,
                op="ACTIONS",
                data={"actions": actions_json},
            )

        async with self._push_rules_stream_id_gen.get_next() as stream_id:
            event_stream_ordering = self._stream_id_gen.get_current_token()

            await self.db_pool.runInteraction(
                "set_push_rule_actions",
                set_push_rule_actions_txn,
                stream_id,
                event_stream_ordering,
            )

    def _insert_push_rules_update_txn(
        self,
        txn: LoggingTransaction,
        stream_id: int,
        event_stream_ordering: int,
        user_id: str,
        rule_id: str,
        op: str,
        data: Optional[JsonDict] = None,
    ) -> None:
        values = {
            "stream_id": stream_id,
            "event_stream_ordering": event_stream_ordering,
            "user_id": user_id,
            "rule_id": rule_id,
            "op": op,
        }
        if data is not None:
            values.update(data)

        self.db_pool.simple_insert_txn(txn, "push_rules_stream", values=values)

        txn.call_after(self.get_push_rules_for_user.invalidate, (user_id,))
        txn.call_after(
            self.push_rules_stream_cache.entity_has_changed, user_id, stream_id
        )

    def get_max_push_rules_stream_id(self) -> int:
        return self._push_rules_stream_id_gen.get_current_token()

    async def copy_push_rule_from_room_to_room(
        self, new_room_id: str, user_id: str, rule: PushRule
    ) -> None:
        """Copy a single push rule from one room to another for a specific user.

        Args:
            new_room_id: ID of the new room.
            user_id : ID of user the push rule belongs to.
            rule: A push rule.
        """
        # Create new rule id
        rule_id_scope = "/".join(rule.rule_id.split("/")[:-1])
        new_rule_id = rule_id_scope + "/" + new_room_id

        new_conditions = []

        # Change room id in each condition
        for condition in rule.conditions:
            new_condition = condition
            if condition.get("key") == "room_id":
                new_condition = dict(condition)
                new_condition["pattern"] = new_room_id

            new_conditions.append(new_condition)

        # Add the rule for the new room
        await self.add_push_rule(
            user_id=user_id,
            rule_id=new_rule_id,
            priority_class=rule.priority_class,
            conditions=new_conditions,
            actions=rule.actions,
        )

    async def copy_push_rules_from_room_to_room_for_user(
        self, old_room_id: str, new_room_id: str, user_id: str
    ) -> None:
        """Copy all of the push rules from one room to another for a specific
        user.

        Args:
            old_room_id: ID of the old room.
            new_room_id: ID of the new room.
            user_id: ID of user to copy push rules for.
        """
        # Retrieve push rules for this user
        user_push_rules = await self.get_push_rules_for_user(user_id)

        # Get rules relating to the old room and copy them to the new room
        for rule, enabled in user_push_rules.rules():
            if not enabled:
                continue

            conditions = rule.conditions
            if any(
                (c.get("key") == "room_id" and c.get("pattern") == old_room_id)
                for c in conditions
            ):
                await self.copy_push_rule_from_room_to_room(new_room_id, user_id, rule)
