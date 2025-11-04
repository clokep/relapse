# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018-2021 The Matrix.org Foundation C.I.C.
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

from typing import TYPE_CHECKING

from PIL.features import check_codec

from relapse.config._base import ConfigError
from relapse.http.server import HttpServer
from relapse.rest.media.config import MediaConfigServlet
from relapse.rest.media.create import CreateServlet
from relapse.rest.media.download import DownloadServlet
from relapse.rest.media.preview_url import PreviewUrlServlet
from relapse.rest.media.thumbnail import ThumbnailServlet
from relapse.rest.media.upload import AsyncUploadServlet, UploadServlet

if TYPE_CHECKING:
    from relapse.server import HomeServer


# check for JPEG support.
if not check_codec("jpg"):
    raise Exception(
        "FATAL: jpeg codec not supported. Install pillow correctly! "
        " 'sudo apt-get install libjpeg-dev' then 'pip uninstall pillow &&"
        " pip install pillow --user'"
    )


# check for PNG support.
if not check_codec("zlib"):
    raise Exception(
        "FATAL: zip codec not supported. Install pillow correctly! "
        " 'sudo apt-get install libjpeg-dev' then 'pip uninstall pillow &&"
        " pip install pillow --user'"
    )


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    """File uploading and downloading.

    Uploads are POSTed to a resource which returns a token which is used to GET
    the download::

        => POST /_matrix/media/r0/upload HTTP/1.1
           Content-Type: <media-type>
           Content-Length: <content-length>

           <media>

        <= HTTP/1.1 200 OK
           Content-Type: application/json

           { "content_uri": "mxc://<server-name>/<media-id>" }

        => GET /_matrix/media/r0/download/<server-name>/<media-id> HTTP/1.1

        <= HTTP/1.1 200 OK
           Content-Type: <media-type>
           Content-Disposition: attachment;filename=<upload-filename>

           <media>

    Clients can get thumbnails by supplying a desired width and height and
    thumbnailing method::

        => GET /_matrix/media/r0/thumbnail/<server_name>
                /<media-id>?width=<w>&height=<h>&method=<m> HTTP/1.1

        <= HTTP/1.1 200 OK
           Content-Type: image/jpeg or image/png

           <thumbnail>

    The thumbnail methods are "crop" and "scale". "scale" tries to return an
    image where either the width or the height is smaller than the requested
    size. The client should then scale and letterbox the image if it needs to
    fit within a given rectangle. "crop" tries to return an image where the
    width and height are close to the requested size and the aspect matches
    the requested size. The client should scale the image if it needs to fit
    within a given rectangle.

    This gets mounted at various points under /_matrix/media, including:
       * /_matrix/media/r0
       * /_matrix/media/v1
       * /_matrix/media/v3
    """

    if not hs.config.media.can_load_media_repo:
        raise ConfigError("Relapse is not configured to use a media repo.")

    media_repo = hs.get_media_repository()

    # Note that many of these should not exist as v1 endpoints, but empirically
    # a lot of traffic still goes to them.
    CreateServlet(hs, media_repo).register(http_server)
    UploadServlet(hs, media_repo).register(http_server)
    AsyncUploadServlet(hs, media_repo).register(http_server)
    DownloadServlet(hs, media_repo).register(http_server)
    ThumbnailServlet(hs, media_repo, media_repo.media_storage).register(http_server)
    if hs.config.media.url_preview_enabled:
        PreviewUrlServlet(hs, media_repo, media_repo.media_storage).register(
            http_server
        )
    MediaConfigServlet(hs).register(http_server)
