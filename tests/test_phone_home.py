# Copyright 2019 Matrix.org Foundation C.I.C.
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


from twisted.internet.testing import MemoryReactor

from relapse.server import HomeServer
from relapse.util import Clock

from tests.unittest import HomeserverTestCase


class CommonMetricsTestCase(HomeserverTestCase):
    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.metrics_manager = hs.get_common_usage_metrics_manager()
        self.get_success(self.metrics_manager.setup())

    def test_dau(self) -> None:
        """Tests that the daily active users count is correctly updated."""
        self._assert_metric_value("daily_active_users", 0)

        self.register_user("user", "password")
        tok = self.login("user", "password")
        self.make_request("GET", "/_matrix/client/r0/sync", access_token=tok)

        self.pump(1)

        self._assert_metric_value("daily_active_users", 1)

    def _assert_metric_value(self, metric_name: str, expected: int) -> None:
        """Compare the given value to the current value of the common usage metric with
        the given name.

        Args:
            metric_name: The metric to look up.
            expected: Expected value for this metric.
        """
        metrics = self.get_success(self.metrics_manager.get_metrics())
        value = getattr(metrics, metric_name)
        self.assertEqual(value, expected)
