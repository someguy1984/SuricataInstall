#!/usr/bin/python3 -I
"""edr-agent: reads the host's logs, raises local alerts and reports to the hub.

This is only the entry point. The code is in the edragent package beside this file. Run it with
`python3 -I`, which keeps the script's directory off sys.path, so the directory is added here.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from edragent import cli  # noqa: E402

if __name__ == "__main__":
    sys.exit(cli.main(sys.argv[1:]))
