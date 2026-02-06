# Copyright 2022 The Matrix.org Foundation C.I.C.
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
from collections.abc import Mapping
from typing import Any
from unittest.mock import Mock

from immutabledict import immutabledict

from relapse.config.workers import WorkerConfig

from tests.unittest import TestCase

_EMPTY_IMMUTABLEDICT: Mapping[str, Any] = immutabledict()


class WorkerDutyConfigTestCase(TestCase):
    def _make_worker_config(
        self,
        worker_app: str,
        worker_name: str | None,
        extras: Mapping[str, Any] = _EMPTY_IMMUTABLEDICT,
    ) -> WorkerConfig:
        root_config = Mock()
        root_config.worker_app = worker_app
        root_config.worker_name = worker_name
        worker_config = WorkerConfig(root_config)
        worker_config_dict = {
            "worker_name": worker_name,
            "worker_app": worker_app,
            **extras,
        }
        worker_config.read_config(worker_config_dict)
        return worker_config

    def test_configs_master(self) -> None:
        """
        Tests config options. This is for the master's config.
        """
        main_process_config = self._make_worker_config(
            worker_app="relapse.app.homeserver",
            worker_name=None,
            extras={"instance_map": {"main": {"host": "127.0.0.1", "port": 0}}},
        )

        self.assertTrue(
            main_process_config._should_this_worker_perform_duty(
                {"notify_appservices_from_worker": None},
                "notify_appservices_from_worker",
            )
        )

        self.assertFalse(
            main_process_config._should_this_worker_perform_duty(
                {"notify_appservices_from_worker": "worker1"},
                "notify_appservices_from_worker",
            )
        )

    def test_configs_appservice_worker(self) -> None:
        """
        Tests config options. This is for the worker's config.
        """
        appservice_worker_config = self._make_worker_config(
            worker_app="relapse.app.generic_worker",
            worker_name="worker1",
            extras={"instance_map": {"main": {"host": "127.0.0.1", "port": 0}}},
        )

        self.assertTrue(
            appservice_worker_config._should_this_worker_perform_duty(
                {
                    "notify_appservices_from_worker": "worker1",
                },
                "notify_appservices_from_worker",
            )
        )

        self.assertFalse(
            appservice_worker_config._should_this_worker_perform_duty(
                {
                    "notify_appservices_from_worker": "worker2",
                },
                "notify_appservices_from_worker",
            )
        )

    def test_worker_duty_configs(self) -> None:
        """
        Additional tests for the worker duties
        """

        worker1_config = self._make_worker_config(
            worker_app="relapse.app.generic_worker",
            worker_name="worker1",
            extras={
                "notify_appservices_from_worker": "worker2",
                "update_user_directory_from_worker": "worker1",
                "instance_map": {"main": {"host": "127.0.0.1", "port": 0}},
            },
        )
        self.assertFalse(worker1_config.should_notify_appservices)
        self.assertTrue(worker1_config.should_update_user_directory)

        worker2_config = self._make_worker_config(
            worker_app="relapse.app.generic_worker",
            worker_name="worker2",
            extras={
                "notify_appservices_from_worker": "worker2",
                "update_user_directory_from_worker": "worker1",
                "instance_map": {"main": {"host": "127.0.0.1", "port": 0}},
            },
        )
        self.assertTrue(worker2_config.should_notify_appservices)
        self.assertFalse(worker2_config.should_update_user_directory)
