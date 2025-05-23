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
from abc import ABC, abstractmethod
from typing import Generic, Optional, TypeVar

from relapse.types import StrCollection, UserID

# The key, this is either a stream token or int.
K = TypeVar("K")
# The return type.
R = TypeVar("R")


class EventSource(ABC, Generic[K, R]):
    @abstractmethod
    async def get_new_events(
        self,
        user: UserID,
        from_key: K,
        limit: int,
        room_ids: StrCollection,
        is_guest: bool,
        explicit_room_id: Optional[str] = None,
    ) -> tuple[list[R], K]:
        raise NotImplementedError()
