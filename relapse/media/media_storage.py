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
import contextlib
import logging
import os
import shutil
from collections.abc import Awaitable, Generator, Sequence
from types import TracebackType
from typing import IO, TYPE_CHECKING, Any, BinaryIO, Callable, Optional

import attr

from twisted.internet.defer import Deferred
from twisted.internet.interfaces import IConsumer
from twisted.protocols.basic import FileSender

from relapse.api.errors import NotFoundError
from relapse.logging.context import defer_to_thread, make_deferred_yieldable
from relapse.logging.opentracing import start_active_span, trace, trace_with_opname
from relapse.util import Clock
from relapse.util.file_consumer import BackgroundFileConsumer

from ._base import FileInfo, Responder
from .filepath import MediaFilePaths

if TYPE_CHECKING:
    from relapse.media.storage_provider import StorageProvider
    from relapse.server import HomeServer

logger = logging.getLogger(__name__)


class MediaStorage:
    """Responsible for storing/fetching files from local sources.

    Args:
        hs
        local_media_directory: Base path where we store media on disk
        filepaths
        storage_providers: List of StorageProvider that are used to fetch and store files.
    """

    def __init__(
        self,
        hs: "HomeServer",
        local_media_directory: str,
        filepaths: MediaFilePaths,
        storage_providers: Sequence["StorageProvider"],
    ):
        self.hs = hs
        self.reactor = hs.get_reactor()
        self.local_media_directory = local_media_directory
        self.filepaths = filepaths
        self.storage_providers = storage_providers
        self._spam_checker_module_callbacks = hs.get_module_api_callbacks().spam_checker
        self.clock = hs.get_clock()

    @trace_with_opname("MediaStorage.store_file")
    async def store_file(self, source: IO, file_info: FileInfo) -> str:
        """Write `source` to the on disk media store, and also any other
        configured storage providers

        Args:
            source: A file like object that should be written
            file_info: Info about the file to store

        Returns:
            the file path written to in the primary media store
        """

        with self.store_into_file(file_info) as (f, fname, finish_cb):
            # Write to the main media repository
            await self.write_to_file(source, f)
            # Write to the other storage providers
            await finish_cb()

        return fname

    @trace_with_opname("MediaStorage.write_to_file")
    async def write_to_file(self, source: IO, output: IO) -> None:
        """Asynchronously write the `source` to `output`."""
        await defer_to_thread(self.reactor, _write_file_synchronously, source, output)

    @trace_with_opname("MediaStorage.store_into_file")
    @contextlib.contextmanager
    def store_into_file(
        self, file_info: FileInfo
    ) -> Generator[tuple[BinaryIO, str, Callable[[], Awaitable[None]]], None, None]:
        """Context manager used to get a file like object to write into, as
        described by file_info.

        Actually yields a 3-tuple (file, fname, finish_cb), where file is a file
        like object that can be written to, fname is the absolute path of file
        on disk, and finish_cb is a function that returns an awaitable.

        fname can be used to read the contents from after upload, e.g. to
        generate thumbnails.

        finish_cb must be called and waited on after the file has been successfully been
        written to. Should not be called if there was an error. Checks for spam and
        stores the file into the configured storage providers.

        Args:
            file_info: Info about the file to store

        Example:

            with media_storage.store_into_file(info) as (f, fname, finish_cb):
                # .. write into f ...
                await finish_cb()
        """

        path = self._file_info_to_path(file_info)
        fname = os.path.join(self.local_media_directory, path)

        dirname = os.path.dirname(fname)
        os.makedirs(dirname, exist_ok=True)

        finished_called = [False]

        main_media_repo_write_trace_scope = start_active_span(
            "writing to main media repo"
        )
        main_media_repo_write_trace_scope.__enter__()

        try:
            with open(fname, "wb") as f:

                async def finish() -> None:
                    # When someone calls finish, we assume they are done writing to the main media repo
                    main_media_repo_write_trace_scope.__exit__(None, None, None)

                    with start_active_span("writing to other storage providers"):
                        # Ensure that all writes have been flushed and close the
                        # file.
                        f.flush()
                        f.close()

                        spam_check = await self._spam_checker_module_callbacks.check_media_file_for_spam(
                            ReadableFileWrapper(self.clock, fname), file_info
                        )
                        if spam_check != self._spam_checker_module_callbacks.NOT_SPAM:
                            logger.info("Blocking media due to spam checker")
                            # Note that we'll delete the stored media, due to the
                            # try/except below. The media also won't be stored in
                            # the DB.
                            # We currently ignore any additional field returned by
                            # the spam-check API.
                            raise SpamMediaException(errcode=spam_check[0])

                        for provider in self.storage_providers:
                            with start_active_span(str(provider)):
                                await provider.store_file(path, file_info)

                        finished_called[0] = True

                yield f, fname, finish
        except Exception as e:
            try:
                main_media_repo_write_trace_scope.__exit__(
                    type(e), None, e.__traceback__
                )
                os.remove(fname)
            except Exception:
                pass

            raise e from None

        if not finished_called:
            exc = Exception("Finished callback not called")
            main_media_repo_write_trace_scope.__exit__(
                type(exc), None, exc.__traceback__
            )
            raise exc

    async def fetch_media(self, file_info: FileInfo) -> Optional[Responder]:
        """Attempts to fetch media described by file_info from the local cache
        and configured storage providers.

        Args:
            file_info

        Returns:
            Returns a Responder if the file was found, otherwise None.
        """
        paths = [self._file_info_to_path(file_info)]

        # fallback for remote thumbnails with no method in the filename
        if file_info.thumbnail and file_info.server_name:
            paths.append(
                self.filepaths.remote_media_thumbnail_rel_legacy(
                    server_name=file_info.server_name,
                    file_id=file_info.file_id,
                    width=file_info.thumbnail.width,
                    height=file_info.thumbnail.height,
                    content_type=file_info.thumbnail.type,
                )
            )

        for path in paths:
            local_path = os.path.join(self.local_media_directory, path)
            if os.path.exists(local_path):
                logger.debug("responding with local file %s", local_path)
                return FileResponder(open(local_path, "rb"))
            logger.debug("local file %s did not exist", local_path)

        for provider in self.storage_providers:
            for path in paths:
                res: Any = await provider.fetch(path, file_info)
                if res:
                    logger.debug("Streaming %s from %s", path, provider)
                    return res
                logger.debug("%s not found on %s", path, provider)

        return None

    @trace
    async def ensure_media_is_in_local_cache(self, file_info: FileInfo) -> str:
        """Ensures that the given file is in the local cache. Attempts to
        download it from storage providers if it isn't.

        Args:
            file_info

        Returns:
            Full path to local file
        """
        path = self._file_info_to_path(file_info)
        local_path = os.path.join(self.local_media_directory, path)
        if os.path.exists(local_path):
            return local_path

        # Fallback for paths without method names
        # Should be removed in the future
        if file_info.thumbnail and file_info.server_name:
            legacy_path = self.filepaths.remote_media_thumbnail_rel_legacy(
                server_name=file_info.server_name,
                file_id=file_info.file_id,
                width=file_info.thumbnail.width,
                height=file_info.thumbnail.height,
                content_type=file_info.thumbnail.type,
            )
            legacy_local_path = os.path.join(self.local_media_directory, legacy_path)
            if os.path.exists(legacy_local_path):
                return legacy_local_path

        dirname = os.path.dirname(local_path)
        os.makedirs(dirname, exist_ok=True)

        for provider in self.storage_providers:
            res: Any = await provider.fetch(path, file_info)
            if res:
                with res:
                    consumer = BackgroundFileConsumer(
                        open(local_path, "wb"), self.reactor
                    )
                    await res.write_to_consumer(consumer)
                    await consumer.wait()
                return local_path

        raise NotFoundError()

    @trace
    def _file_info_to_path(self, file_info: FileInfo) -> str:
        """Converts file_info into a relative path.

        The path is suitable for storing files under a directory, e.g. used to
        store files on local FS under the base media repository directory.
        """
        if file_info.url_cache:
            if file_info.thumbnail:
                return self.filepaths.url_cache_thumbnail_rel(
                    media_id=file_info.file_id,
                    width=file_info.thumbnail.width,
                    height=file_info.thumbnail.height,
                    content_type=file_info.thumbnail.type,
                    method=file_info.thumbnail.method,
                )
            return self.filepaths.url_cache_filepath_rel(file_info.file_id)

        if file_info.server_name:
            if file_info.thumbnail:
                return self.filepaths.remote_media_thumbnail_rel(
                    server_name=file_info.server_name,
                    file_id=file_info.file_id,
                    width=file_info.thumbnail.width,
                    height=file_info.thumbnail.height,
                    content_type=file_info.thumbnail.type,
                    method=file_info.thumbnail.method,
                )
            return self.filepaths.remote_media_filepath_rel(
                file_info.server_name, file_info.file_id
            )

        if file_info.thumbnail:
            return self.filepaths.local_media_thumbnail_rel(
                media_id=file_info.file_id,
                width=file_info.thumbnail.width,
                height=file_info.thumbnail.height,
                content_type=file_info.thumbnail.type,
                method=file_info.thumbnail.method,
            )
        return self.filepaths.local_media_filepath_rel(file_info.file_id)


@trace
def _write_file_synchronously(source: IO, dest: IO) -> None:
    """Write `source` to the file like `dest` synchronously. Should be called
    from a thread.

    Args:
        source: A file like object that's to be written
        dest: A file like object to be written to
    """
    source.seek(0)  # Ensure we read from the start of the file
    shutil.copyfileobj(source, dest)


class FileResponder(Responder):
    """Wraps an open file that can be sent to a request.

    Args:
        open_file: A file like object to be streamed ot the client,
            is closed when finished streaming.
    """

    def __init__(self, open_file: IO):
        self.open_file = open_file

    def write_to_consumer(self, consumer: IConsumer) -> Deferred:
        return make_deferred_yieldable(
            FileSender().beginFileTransfer(self.open_file, consumer)
        )

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        self.open_file.close()


class SpamMediaException(NotFoundError):
    """The media was blocked by a spam checker, so we simply 404 the request (in
    the same way as if it was quarantined).
    """


@attr.s(slots=True, auto_attribs=True)
class ReadableFileWrapper:
    """Wrapper that allows reading a file in chunks, yielding to the reactor,
    and writing to a callback.

    This is simplified `FileSender` that takes an IO object rather than an
    `IConsumer`.
    """

    CHUNK_SIZE = 2**14

    clock: Clock
    path: str

    async def write_chunks_to(self, callback: Callable[[bytes], object]) -> None:
        """Reads the file in chunks and calls the callback with each chunk."""

        with open(self.path, "rb") as file:
            while True:
                chunk = file.read(self.CHUNK_SIZE)
                if not chunk:
                    break

                callback(chunk)

                # We yield to the reactor by sleeping for 0 seconds.
                await self.clock.sleep(0)
