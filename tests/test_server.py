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

import re
from http import HTTPStatus
from typing import NoReturn

from twisted.internet.defer import Deferred

from relapse.api.errors import Codes, RelapseError
from relapse.http.server import JsonResource, respond_with_html_bytes
from relapse.http.servlet import RestServlet
from relapse.http.site import RelapseRequest
from relapse.logging.context import make_deferred_yieldable
from relapse.server import HomeServer
from relapse.types import JsonDict
from relapse.util.cancellation import cancellable

from tests import unittest
from tests.http.server._base import test_disconnect
from tests.server import (
    FakeChannel,
    FakeSite,
    get_clock,
    make_request,
    setup_test_homeserver,
)


class JsonResourceTests(unittest.TestCase):
    def setUp(self) -> None:
        reactor, clock = get_clock()
        self.reactor = reactor
        self.homeserver = setup_test_homeserver(
            self.addCleanup,
            clock=clock,
            reactor=self.reactor,
        )

    def test_handler_for_request(self) -> None:
        """
        JsonResource.handler_for_request gives correctly decoded URL args to
        the callback, while Twisted will give the raw bytes of URL query
        arguments.
        """
        got_kwargs = {}

        def _callback(
            request: RelapseRequest, **kwargs: object
        ) -> tuple[int, dict[str, object]]:
            got_kwargs.update(kwargs)
            return 200, kwargs

        res = JsonResource(self.homeserver)
        res.register_paths(
            "GET",
            [re.compile("^/_matrix/foo/(?P<room_id>[^/]*)$")],
            _callback,
            "test_servlet",
        )

        make_request(
            self.reactor,
            FakeSite(res, self.reactor),
            b"GET",
            b"/_matrix/foo/%E2%98%83?a=%E2%98%83",
        )

        self.assertEqual(got_kwargs, {"room_id": "\N{SNOWMAN}"})

    def test_callback_direct_exception(self) -> None:
        """
        If the web callback raises an uncaught exception, it will be translated
        into a 500.
        """

        def _callback(request: RelapseRequest, **kwargs: object) -> NoReturn:
            raise Exception("boo")

        res = JsonResource(self.homeserver)
        res.register_paths(
            "GET", [re.compile("^/_matrix/foo$")], _callback, "test_servlet"
        )

        channel = make_request(
            self.reactor, FakeSite(res, self.reactor), b"GET", b"/_matrix/foo"
        )

        self.assertEqual(channel.code, 500)

    def test_callback_indirect_exception(self) -> None:
        """
        If the web callback raises an uncaught exception in a Deferred, it will
        be translated into a 500.
        """

        def _throw(*args: object) -> NoReturn:
            raise Exception("boo")

        def _callback(request: RelapseRequest, **kwargs: object) -> "Deferred[None]":
            d: Deferred[None] = Deferred()
            d.addCallback(_throw)
            self.reactor.callLater(0.5, d.callback, True)
            return make_deferred_yieldable(d)

        res = JsonResource(self.homeserver)
        res.register_paths(
            "GET", [re.compile("^/_matrix/foo$")], _callback, "test_servlet"
        )

        channel = make_request(
            self.reactor, FakeSite(res, self.reactor), b"GET", b"/_matrix/foo"
        )

        self.assertEqual(channel.code, 500)

    def test_callback_relapseerror(self) -> None:
        """
        If the web callback raises a RelapseError, it returns the appropriate
        status code and message set in it.
        """

        def _callback(request: RelapseRequest, **kwargs: object) -> NoReturn:
            raise RelapseError(403, "Forbidden!!one!", Codes.FORBIDDEN)

        res = JsonResource(self.homeserver)
        res.register_paths(
            "GET", [re.compile("^/_matrix/foo$")], _callback, "test_servlet"
        )

        channel = make_request(
            self.reactor, FakeSite(res, self.reactor), b"GET", b"/_matrix/foo"
        )

        self.assertEqual(channel.code, 403)
        self.assertEqual(channel.json_body["error"], "Forbidden!!one!")
        self.assertEqual(channel.json_body["errcode"], "M_FORBIDDEN")

    def test_no_handler(self) -> None:
        """
        If there is no handler to process the request, Relapse will return 400.
        """

        def _callback(request: RelapseRequest, **kwargs: object) -> None:
            """
            Not ever actually called!
            """
            self.fail("shouldn't ever get here")

        res = JsonResource(self.homeserver)
        res.register_paths(
            "GET", [re.compile("^/_matrix/foo$")], _callback, "test_servlet"
        )

        channel = make_request(
            self.reactor, FakeSite(res, self.reactor), b"GET", b"/_matrix/foobar"
        )

        self.assertEqual(channel.code, 404)
        self.assertEqual(channel.json_body["error"], "Unrecognized request")
        self.assertEqual(channel.json_body["errcode"], "M_UNRECOGNIZED")

    def test_head_request(self) -> None:
        """
        JsonResource.handler_for_request gives correctly decoded URL args to
        the callback, while Twisted will give the raw bytes of URL query
        arguments.
        """

        def _callback(
            request: RelapseRequest, **kwargs: object
        ) -> tuple[int, dict[str, object]]:
            return 200, {"result": True}

        res = JsonResource(self.homeserver)
        res.register_paths(
            "GET",
            [re.compile("^/_matrix/foo$")],
            _callback,
            "test_servlet",
        )

        # The path was registered as GET, but this is a HEAD request.
        channel = make_request(
            self.reactor, FakeSite(res, self.reactor), b"HEAD", b"/_matrix/foo"
        )

        self.assertEqual(channel.code, 200)
        self.assertNotIn("body", channel.result)


class OptionsResourceTests(unittest.HomeserverTestCase):
    class DummyServlet(RestServlet):
        PATTERNS = [re.compile(r"^/_matrix/res/$")]

        async def on_GET(self, request: RelapseRequest) -> None:
            respond_with_html_bytes(request, 200, request.path)

    servlets = [
        lambda hs, http_server: OptionsResourceTests.DummyServlet().register(
            http_server
        )
    ]

    def _check_cors_standard_headers(self, channel: FakeChannel) -> None:
        # Ensure the correct CORS headers have been added
        # as per https://spec.matrix.org/v1.4/client-server-api/#web-browser-clients
        self.assertEqual(
            channel.headers.getRawHeaders(b"Access-Control-Allow-Origin"),
            [b"*"],
            "has correct CORS Origin header",
        )
        self.assertEqual(
            channel.headers.getRawHeaders(b"Access-Control-Allow-Methods"),
            [b"GET, HEAD, POST, PUT, DELETE, OPTIONS"],  # HEAD isn't in the spec
            "has correct CORS Methods header",
        )
        self.assertEqual(
            channel.headers.getRawHeaders(b"Access-Control-Allow-Headers"),
            [b"X-Requested-With, Content-Type, Authorization, Date"],
            "has correct CORS Headers header",
        )
        self.assertEqual(
            channel.headers.getRawHeaders(b"Access-Control-Expose-Headers"),
            [b"Relapse-Trace-Id, Server"],
        )

    def test_unknown_options_request(self) -> None:
        """An OPTIONS requests to an unknown URL still returns 204 No Content."""
        channel = self.make_request(b"OPTIONS", b"/_matrix/foo/")
        self.assertEqual(channel.code, 204)
        self.assertNotIn("body", channel.result)

        self._check_cors_standard_headers(channel)

    def test_known_options_request(self) -> None:
        """An OPTIONS requests to an known URL still returns 204 No Content."""
        channel = self.make_request(b"OPTIONS", b"/_matrix/res/")
        self.assertEqual(channel.code, 204)
        self.assertNotIn("body", channel.result)

        self._check_cors_standard_headers(channel)

    def test_unknown_request(self) -> None:
        """A non-OPTIONS request to an unknown URL should 404."""
        channel = self.make_request(b"GET", b"/_matrix/foo/")
        self.assertEqual(channel.code, 404)

    def test_known_request(self) -> None:
        """A non-OPTIONS request to an known URL should query the proper resource."""
        channel = self.make_request(b"GET", b"/_matrix/res/")
        self.assertEqual(channel.code, 200)
        self.assertEqual(channel.result["body"], b"/_matrix/res/")


class CancellableRestServlet(RestServlet):
    PATTERNS = [re.compile(r"/_matrix/client/sleep")]

    def __init__(self, hs: HomeServer) -> None:
        self.clock = hs.get_clock()

    @cancellable
    async def on_GET(self, request: RelapseRequest) -> tuple[int, JsonDict]:
        await self.clock.sleep(1.0)
        return HTTPStatus.OK, {"result": True}

    async def on_POST(self, request: RelapseRequest) -> tuple[int, JsonDict]:
        await self.clock.sleep(1.0)
        return HTTPStatus.OK, {"result": True}


class JsonResourceCancellationTests(unittest.HomeserverTestCase):
    """Tests for `JsonResource` cancellation."""

    servlets = [
        lambda hs, http_server: CancellableRestServlet(hs).register(http_server)
    ]

    def test_cancellable_disconnect(self) -> None:
        """Test that handlers with the `@cancellable` flag can be cancelled."""
        channel = self.make_request(
            "GET",
            "/_matrix/client/sleep",
            await_result=False,
            shorthand=False,
        )
        test_disconnect(
            self.reactor,
            channel,
            expect_cancellation=True,
            expected_body={"error": "Request cancelled", "errcode": Codes.UNKNOWN},
        )

    def test_uncancellable_disconnect(self) -> None:
        """Test that handlers without the `@cancellable` flag cannot be cancelled."""
        channel = self.make_request(
            "POST",
            "/_matrix/client/sleep",
            await_result=False,
            shorthand=False,
        )
        test_disconnect(
            self.reactor,
            channel,
            expect_cancellation=False,
            expected_body={"result": True},
        )
