# Copyright 2014 Christian Buia
# Copyright 2025 plyara Maintainers
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
"""plyara command line script.

This module contains command line script for parsing rules.
"""
import argparse
import json
import logging
import pathlib
import sys

import plyara.core
from plyara.review import review_rules


def _set_logging():
    """Set the console logger."""
    logger = logging.getLogger('plyara')
    logger.setLevel(logging.DEBUG)
    sh = logging.StreamHandler()
    sh.setLevel(logging.DEBUG)
    logger.addHandler(sh)


def main(argv=None):
    """Run the command line process to parse or review YARA rules.

    Args:
        argv: Optional argument list without the program name. Defaults to ``sys.argv[1:]``.
    """
    arg_parser = argparse.ArgumentParser(description='Parse YARA rules into a JSON representation.')
    arg_parser.add_argument('file', metavar='FILE', nargs='?', help='File containing YARA rules to parse.')
    arg_parser.add_argument(
        '--review',
        nargs=3,
        metavar=('BASE', 'LEFT', 'RIGHT'),
        help='Three-way review two complete drafts against an approved base ruleset.',
    )
    arg_parser.add_argument('--log', help='Enable debug logging to the console.', action='store_true')

    cli_args = list(sys.argv[1:] if argv is None else argv)
    if cli_args and cli_args[0] == 'review':
        args = arg_parser.parse_args(['--review', *cli_args[1:]])
    elif cli_args and cli_args[0] == '--review':
        args = arg_parser.parse_args(cli_args)
    elif argv is not None:
        args = arg_parser.parse_args(cli_args)
    else:
        args = arg_parser.parse_args()

    if args.log:
        _set_logging()

    if args.review:
        base_file, left_file, right_file = args.review
        base = _read_source(base_file)
        left = _read_source(left_file)
        right = _read_source(right_file)
        report = review_rules(
            base,
            left,
            right,
            base_label=base_file,
            left_label=left_file,
            right_label=right_file,
        )
        print(json.dumps(report.to_dict(), sort_keys=True, indent=4))
        return

    if args.file is None:
        arg_parser.error('a FILE or --review BASE LEFT RIGHT is required')

    input_string = _read_source(args.file)

    yara_parser = plyara.core.Plyara()

    rules = yara_parser.parse_string(input_string)

    print(json.dumps(rules, sort_keys=True, indent=4))


def _read_source(path):
    """Read a YARA source file, preserving the CLI's file-not-found behavior."""
    try:
        return pathlib.Path(path).read_text(encoding='utf-8')
    except FileNotFoundError as e:
        sys.exit(e)


if __name__ == '__main__':
    main()
