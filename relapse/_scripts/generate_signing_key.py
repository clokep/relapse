#!/usr/bin/env python
# Copyright 2019 The Matrix.org Foundation C.I.C.
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
import argparse
import os
import sys

from signedjson.key import generate_signing_key, write_signing_keys

from relapse.util.stringutils import random_string


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-o",
        "--output_file",
        type=str,
        default="-",
        help="Where to write the output to",
    )
    args = parser.parse_args()

    key_id = "a_" + random_string(4)
    key = (generate_signing_key(key_id),)
    if args.output_file == "-":
        write_signing_keys(sys.stdout, key)
    else:
        with open(
            args.output_file, "w", opener=lambda p, f: os.open(p, f, mode=0o640)
        ) as signing_key_file:
            write_signing_keys(signing_key_file, key)


if __name__ == "__main__":
    main()
