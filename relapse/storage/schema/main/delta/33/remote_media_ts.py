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

import time

from relapse.config.homeserver import HomeServerConfig
from relapse.storage.database import LoggingTransaction
from relapse.storage.engines import BaseDatabaseEngine

ALTER_TABLE = "ALTER TABLE remote_media_cache ADD COLUMN last_access_ts BIGINT"


def run_create(cur: LoggingTransaction, database_engine: BaseDatabaseEngine) -> None:
    cur.execute(ALTER_TABLE)


def run_upgrade(
    cur: LoggingTransaction,
    database_engine: BaseDatabaseEngine,
    config: HomeServerConfig,
) -> None:
    cur.execute(
        "UPDATE remote_media_cache SET last_access_ts = ?",
        (int(time.time() * 1000),),
    )
