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
#
# ## What this script does
#
# This script spawns multiple workers, whilst only going through the code loading
# process once. The net effect is that start-up time for a swarm of workers is
# reduced, particularly in CPU-constrained environments.
#
# Before the workers are spawned, the database is prepared in order to avoid the
# workers racing.
#
# ## Stability
#
# This script is only intended for use within the Relapse images for the
# Complement test suite.
# There are currently no stability guarantees whatsoever; especially not about:
# - whether it will continue to exist in future versions;
# - the format of its command-line arguments; or
# - any details about its behaviour or principles of operation.
#
# ## Usage
#
# The first argument should be the path to the database configuration, used to
# set up the database. The rest of the arguments are used as follows:
# Each worker is specified as an argument group (each argument group is
# separated by '--').
# The first argument in each argument group is the Python module name of the application
# to start. Further arguments are then passed to that module as-is.
#
# ## Example
#
#   python -m relapse.app.complement_fork_starter path_to_db_config.yaml \
#     relapse.app.homeserver [args..] -- \
#     relapse.app.generic_worker [args..] -- \
#   ...
#     relapse.app.generic_worker [args..]
#
import argparse
import importlib
import itertools
import multiprocessing
import os
import signal
import sys
from types import FrameType
from typing import Any, Callable, Optional

# a list of the original signal handlers, before we installed our custom ones.
# We restore these in our child processes.
_original_signal_handlers: dict[int, Any] = {}


def _worker_entrypoint(func: Callable[[], None], args: list[str]) -> None:
    """
    Entrypoint for a forked worker process.

    We just need to set up the command-line arguments, create our real reactor
    and then kick off the worker's main() function.
    """

    sys.argv = args

    # reset the custom signal handlers that we installed, so that the children start
    # from a clean slate.
    for sig, handler in _original_signal_handlers.items():
        signal.signal(sig, handler)

    func()


def main() -> None:
    """
    Entrypoint for the forking launcher.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("db_config", help="Path to database config file")
    parser.add_argument(
        "args",
        nargs="...",
        help="Argument groups separated by `--`. "
        "The first argument of each group is a Relapse app name. "
        "Subsequent arguments are passed through.",
    )
    ns = parser.parse_args()

    # Split up the subsequent arguments into each workers' arguments;
    # `--` is our delimiter of choice.
    args_by_worker: list[list[str]] = [
        list(args)
        for cond, args in itertools.groupby(ns.args, lambda ele: ele != "--")
        if cond and args
    ]

    # Import the entrypoints for all the workers.
    worker_functions = []
    for worker_args in args_by_worker:
        worker_module = importlib.import_module(worker_args[0])
        worker_functions.append(worker_module.main)

    # We need to prepare the database first as otherwise all the workers will
    # try to create a schema version table and some will crash out.
    from relapse._scripts import update_relapse_database

    update_proc = multiprocessing.Process(
        target=_worker_entrypoint,
        args=(
            update_relapse_database.main,
            [
                "update_relapse_database",
                "--database-config",
                ns.db_config,
                "--run-background-updates",
            ],
        ),
    )
    print("===== PREPARING DATABASE =====", file=sys.stderr)
    update_proc.start()
    update_proc.join()
    print("===== PREPARED DATABASE =====", file=sys.stderr)

    processes: list[multiprocessing.Process] = []

    # Install signal handlers to propagate signals to all our children, so that they
    # shut down cleanly. This also inhibits our own exit, but that's good: we want to
    # wait until the children have exited.
    def handle_signal(signum: int, frame: Optional[FrameType]) -> None:
        print(
            f"complement_fork_starter: Caught signal {signum}. Stopping children.",
            file=sys.stderr,
        )
        for p in processes:
            if p.pid:
                os.kill(p.pid, signum)

    for sig in (signal.SIGINT, signal.SIGTERM):
        _original_signal_handlers[sig] = signal.signal(sig, handle_signal)

    # At this point, we've imported all the main entrypoints for all the workers.
    # Now we basically just fork() out to create the workers we need.
    # Because we're using fork(), all the workers get a clone of this launcher's
    # memory space and don't need to repeat the work of loading the code!
    # Instead of using fork() directly, we use the multiprocessing library,
    # which uses fork() on Unix platforms.
    for func, worker_args in zip(worker_functions, args_by_worker):
        process = multiprocessing.Process(
            target=_worker_entrypoint, args=(func, worker_args)
        )
        process.start()
        processes.append(process)

    # Be a good parent and wait for our children to die before exiting.
    for process in processes:
        process.join()


if __name__ == "__main__":
    main()
