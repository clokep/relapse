# Copyright 2017 OpenMarket Ltd
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

from typing import cast

from relapse.util import Clock
from relapse.util.caches.expiringcache import ExpiringCache

from tests.utils import MockClock

from .. import unittest


class ExpiringCacheTestCase(unittest.HomeserverTestCase):
    def test_get_set(self) -> None:
        clock = MockClock()
        cache: ExpiringCache[str, str] = ExpiringCache(
            "test", cast(Clock, clock), max_len=1
        )

        cache["key"] = "value"
        self.assertEqual(cache.get("key"), "value")
        self.assertEqual(cache["key"], "value")

    def test_eviction(self) -> None:
        clock = MockClock()
        cache: ExpiringCache[str, str] = ExpiringCache(
            "test", cast(Clock, clock), max_len=2
        )

        cache["key"] = "value"
        cache["key2"] = "value2"
        self.assertEqual(cache.get("key"), "value")
        self.assertEqual(cache.get("key2"), "value2")

        cache["key3"] = "value3"
        self.assertEqual(cache.get("key"), None)
        self.assertEqual(cache.get("key2"), "value2")
        self.assertEqual(cache.get("key3"), "value3")

    def test_iterable_eviction(self) -> None:
        clock = MockClock()
        cache: ExpiringCache[str, list[int]] = ExpiringCache(
            "test", cast(Clock, clock), max_len=5, iterable=True
        )

        cache["key"] = [1]
        cache["key2"] = [2, 3]
        cache["key3"] = [4, 5]

        self.assertEqual(cache.get("key"), [1])
        self.assertEqual(cache.get("key2"), [2, 3])
        self.assertEqual(cache.get("key3"), [4, 5])

        cache["key4"] = [6, 7]
        self.assertEqual(cache.get("key"), None)
        self.assertEqual(cache.get("key2"), None)
        self.assertEqual(cache.get("key3"), [4, 5])
        self.assertEqual(cache.get("key4"), [6, 7])

    def test_time_eviction(self) -> None:
        clock = MockClock()
        cache: ExpiringCache[str, int] = ExpiringCache(
            "test", cast(Clock, clock), expiry_ms=1000
        )

        cache["key"] = 1
        clock.advance_time(0.5)
        cache["key2"] = 2

        self.assertEqual(cache.get("key"), 1)
        self.assertEqual(cache.get("key2"), 2)

        clock.advance_time(0.9)
        self.assertEqual(cache.get("key"), None)
        self.assertEqual(cache.get("key2"), 2)

        clock.advance_time(1)
        self.assertEqual(cache.get("key"), None)
        self.assertEqual(cache.get("key2"), None)
