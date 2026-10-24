# Lets `python -m certavert_scan` work like the `certavert-scan` command.
from certavert_scan.cli import main

raise SystemExit(main())
