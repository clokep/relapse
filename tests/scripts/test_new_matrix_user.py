# Copyright 2018 New Vector
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

from typing import Optional
from unittest.mock import Mock, patch

from relapse._scripts.register_new_matrix_user import request_registration
from relapse.types import JsonDict

from tests.unittest import TestCase


class RegisterTestCase(TestCase):
    def test_success(self) -> None:
        """
        The script will fetch a nonce, and then generate a MAC with it, and then
        post that MAC.
        """

        def get(url: str, verify: Optional[bool] = None) -> Mock:
            r = Mock()
            r.status_code = 200
            r.json = lambda: {"nonce": "a"}
            return r

        def post(
            url: str, json: Optional[JsonDict] = None, verify: Optional[bool] = None
        ) -> Mock:
            # Make sure we are sent the correct info
            assert json is not None
            self.assertEqual(json["username"], "user")
            self.assertEqual(json["password"], "pass")
            self.assertEqual(json["nonce"], "a")
            # We want a 40-char hex MAC
            self.assertEqual(len(json["mac"]), 40)

            r = Mock()
            r.status_code = 200
            return r

        requests = Mock()
        requests.get = get
        requests.post = post

        # The fake stdout will be written here
        out: list[str] = []
        err_code: list[int] = []

        with patch("relapse._scripts.register_new_matrix_user.requests", requests):
            request_registration(
                "user",
                "pass",
                "matrix.org",
                "shared",
                admin=False,
                _print=out.append,
                exit=err_code.append,
            )

        # We should get the success message making sure everything is OK.
        self.assertIn("Success!", out)

        # sys.exit shouldn't have been called.
        self.assertEqual(err_code, [])

    def test_failure_nonce(self) -> None:
        """
        If the script fails to fetch a nonce, it throws an error and quits.
        """

        def get(url: str, verify: Optional[bool] = None) -> Mock:
            r = Mock()
            r.status_code = 404
            r.reason = "Not Found"
            r.json = lambda: {"not": "error"}
            return r

        requests = Mock()
        requests.get = get

        # The fake stdout will be written here
        out: list[str] = []
        err_code: list[int] = []

        with patch("relapse._scripts.register_new_matrix_user.requests", requests):
            request_registration(
                "user",
                "pass",
                "matrix.org",
                "shared",
                admin=False,
                _print=out.append,
                exit=err_code.append,
            )

        # Exit was called
        self.assertEqual(err_code, [1])

        # We got an error message
        self.assertIn("ERROR! Received 404 Not Found", out)
        self.assertNotIn("Success!", out)

    def test_failure_post(self) -> None:
        """
        The script will fetch a nonce, and then if the final POST fails, will
        report an error and quit.
        """

        def get(url: str, verify: Optional[bool] = None) -> Mock:
            r = Mock()
            r.status_code = 200
            r.json = lambda: {"nonce": "a"}
            return r

        def post(
            url: str, json: Optional[JsonDict] = None, verify: Optional[bool] = None
        ) -> Mock:
            # Make sure we are sent the correct info
            assert json is not None
            self.assertEqual(json["username"], "user")
            self.assertEqual(json["password"], "pass")
            self.assertEqual(json["nonce"], "a")
            # We want a 40-char hex MAC
            self.assertEqual(len(json["mac"]), 40)

            r = Mock()
            # Then 500 because we're jerks
            r.status_code = 500
            r.reason = "Broken"
            return r

        requests = Mock()
        requests.get = get
        requests.post = post

        # The fake stdout will be written here
        out: list[str] = []
        err_code: list[int] = []

        with patch("relapse._scripts.register_new_matrix_user.requests", requests):
            request_registration(
                "user",
                "pass",
                "matrix.org",
                "shared",
                admin=False,
                _print=out.append,
                exit=err_code.append,
            )

        # Exit was called
        self.assertEqual(err_code, [1])

        # We got an error message
        self.assertIn("ERROR! Received 500 Broken", out)
        self.assertNotIn("Success!", out)
