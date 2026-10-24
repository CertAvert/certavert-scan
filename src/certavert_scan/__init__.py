"""certavert-scan: find the TLS certificates on your network and see when they expire.

How the code is laid out, in the order a scan runs:

- cli.py       the command line and the run itself (start reading here)
- config.py    the settings file: finding it, reading it, writing the first one
- targets.py   turns "10.0.0.0/24", "host:8443"… into addresses and ports
- probe.py     connects to one address and port and reads its certificate
- certinfo.py  turns a certificate into readable fields (names, dates, key…)
- output.py    writes the HTML, CSV and JSON files

Nothing in this package sends data anywhere: it only connects to the
addresses being scanned (and DNS), and writes files on this machine.
"""

__version__ = "0.1.0"

# The JSON file's format. Bump when a field changes meaning or goes away;
# adding fields keeps the version.
FORMAT_VERSION = 1
