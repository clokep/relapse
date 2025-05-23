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

import logging
from typing import TYPE_CHECKING, Generic, Optional, TypeVar

from relapse.storage._base import SQLBaseStore
from relapse.storage.database import DatabasePool, make_conn
from relapse.storage.databases.main.events import PersistEventsStore
from relapse.storage.databases.state import StateGroupDataStore
from relapse.storage.engines import create_engine
from relapse.storage.prepare_database import prepare_database

if TYPE_CHECKING:
    from relapse.server import HomeServer
    from relapse.storage.databases.main import DataStore

logger = logging.getLogger(__name__)


DataStoreT = TypeVar("DataStoreT", bound=SQLBaseStore, covariant=True)


class Databases(Generic[DataStoreT]):
    """The various databases.

    These are low level interfaces to physical databases.

    Attributes:
        databases
        main
        state
        persist_events
    """

    databases: list[DatabasePool]
    main: "DataStore"  # FIXME: https://github.com/matrix-org/synapse/issues/11165: actually an instance of `main_store_class`
    state: StateGroupDataStore
    persist_events: Optional[PersistEventsStore]

    def __init__(self, main_store_class: type[DataStoreT], hs: "HomeServer"):
        # Note we pass in the main store class here as workers use a different main
        # store.

        self.databases = []
        main: Optional[DataStoreT] = None
        state: Optional[StateGroupDataStore] = None
        persist_events: Optional[PersistEventsStore] = None

        for database_config in hs.config.database.databases:
            db_name = database_config.name
            engine = create_engine(database_config.config)

            with make_conn(database_config, engine, "startup") as db_conn:
                logger.info("[database config %r]: Checking database server", db_name)
                engine.check_database(db_conn)

                logger.info(
                    "[database config %r]: Preparing for databases %r",
                    db_name,
                    database_config.databases,
                )
                prepare_database(
                    db_conn,
                    engine,
                    hs.config,
                    databases=database_config.databases,
                )

                database = DatabasePool(hs, database_config, engine)

                if "main" in database_config.databases:
                    logger.info(
                        "[database config %r]: Starting 'main' database", db_name
                    )

                    # Sanity check we don't try and configure the main store on
                    # multiple databases.
                    if main:
                        raise Exception("'main' data store already configured")

                    main = main_store_class(database, db_conn, hs)

                    # If we're on a process that can persist events also
                    # instantiate a `PersistEventsStore`
                    if hs.get_instance_name() in hs.config.worker.writers.events:
                        persist_events = PersistEventsStore(hs, database, main, db_conn)  # type: ignore[arg-type]

                if "state" in database_config.databases:
                    logger.info(
                        "[database config %r]: Starting 'state' database", db_name
                    )

                    # Sanity check we don't try and configure the state store on
                    # multiple databases.
                    if state:
                        raise Exception("'state' data store already configured")

                    state = StateGroupDataStore(database, db_conn, hs)

                db_conn.commit()

                self.databases.append(database)

                logger.info("[database config %r]: prepared", db_name)

            # Closing the context manager doesn't close the connection.
            # psycopg will close the connection when the object gets GCed, but *only*
            # if the PID is the same as when the connection was opened [1], and
            # it may not be if we fork in the meantime.
            #
            # [1]: https://github.com/psycopg/psycopg2/blob/2_8_5/psycopg/connection_type.c#L1378

            db_conn.close()

        # Sanity check that we have actually configured all the required stores.
        if not main:
            raise Exception("No 'main' database configured")

        if not state:
            raise Exception("No 'state' database configured")

        # We use local variables here to ensure that the databases do not have
        # optional types.
        self.main = main  # type: ignore[assignment]
        self.state = state
        self.persist_events = persist_events
