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

from typing import Any

from relapse.config._base import Config
from relapse.types import JsonDict
from relapse.util.check_dependencies import check_requirements


class RedisConfig(Config):
    section = "redis"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        redis_config = config.get("redis") or {}
        self.redis_enabled = redis_config.get("enabled", False)

        if not self.redis_enabled:
            return

        check_requirements("redis")

        self.redis_host = redis_config.get("host", "localhost")
        self.redis_port = redis_config.get("port", 6379)
        self.redis_path = redis_config.get("path", None)
        self.redis_dbid = redis_config.get("dbid", None)
        self.redis_password = redis_config.get("password")

        self.redis_use_tls = redis_config.get("use_tls", False)
        self.redis_certificate = redis_config.get("certificate_file", None)
        self.redis_private_key = redis_config.get("private_key_file", None)
        self.redis_ca_file = redis_config.get("ca_file", None)
        self.redis_ca_path = redis_config.get("ca_path", None)
