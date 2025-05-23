# Copyright 2016 OpenMarket Ltd
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
from collections.abc import Iterable
from typing import cast

from relapse.config.appservice import load_appservices
from relapse.config.homeserver import HomeServerConfig
from relapse.storage.database import LoggingTransaction
from relapse.storage.engines import BaseDatabaseEngine

logger = logging.getLogger(__name__)


def run_create(cur: LoggingTransaction, database_engine: BaseDatabaseEngine) -> None:
    # NULL indicates user was not registered by an appservice.
    try:
        cur.execute("ALTER TABLE users ADD COLUMN appservice_id TEXT")
    except Exception:
        # Maybe we already added the column? Hope so...
        pass


def run_upgrade(
    cur: LoggingTransaction,
    database_engine: BaseDatabaseEngine,
    config: HomeServerConfig,
) -> None:
    cur.execute("SELECT name FROM users")
    rows = cast(Iterable[tuple[str]], cur.fetchall())

    config_files = []
    try:
        config_files = config.appservice.app_service_config_files
    except AttributeError:
        logger.warning("Could not get app_service_config_files from config")

    appservices = load_appservices(config.server.server_name, config_files)

    owned: dict[str, list[str]] = {}

    for row in rows:
        user_id = row[0]
        for appservice in appservices:
            if appservice.is_exclusive_user(user_id):
                if user_id in owned.keys():
                    logger.error(
                        "user_id %s was owned by more than one application"
                        " service (IDs %s and %s); assigning arbitrarily to %s"
                        % (user_id, owned[user_id], appservice.id, owned[user_id])
                    )
                owned.setdefault(appservice.id, []).append(user_id)

    for as_id, user_ids in owned.items():
        n = 100
        user_chunks = (user_ids[i : i + 100] for i in range(0, len(user_ids), n))
        for chunk in user_chunks:
            cur.execute(
                "UPDATE users SET appservice_id = ? WHERE name IN (%s)"
                % (",".join("?" for _ in chunk),),
                [as_id] + chunk,
            )
