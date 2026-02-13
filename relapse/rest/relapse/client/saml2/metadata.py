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
import logging
import re
from typing import TYPE_CHECKING

import saml2.metadata

from twisted.web.server import Request

from relapse.http.server import finish_request
from relapse.http.servlet import RestServlet

if TYPE_CHECKING:
    from relapse.server import HomeServer

logger = logging.getLogger(__name__)


class SAML2MetadataServlet(RestServlet):
    """A servlet which renders the SAML metadata"""

    PATTERNS = [re.compile(r"/_relapse/client/saml2/metadata\.xml$")]

    def __init__(self, hs: "HomeServer"):
        self.sp_config = hs.config.saml2.saml2_sp_config

    def on_GET(self, request: Request) -> None:
        metadata_xml = saml2.metadata.create_metadata_string(
            configfile=None, config=self.sp_config
        )

        # The response code must always be set, for logging purposes.
        request.setResponseCode(200)

        # could alternatively use request.notifyFinish() and flip a flag when
        # the Deferred fires, but since the flag is RIGHT THERE it seems like
        # a waste.
        if request._disconnected:
            logger.warning(
                "Not sending response to request %s, already disconnected.", request
            )
            return

        request.setHeader(b"Content-Type", b"text/xml; charset=utf-8")
        request.setHeader(b"Content-Length", b"%d" % (len(metadata_xml),))

        request.write(metadata_xml)
        finish_request(request)
