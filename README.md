# certavert-scan

Find the TLS certificates on your network and see when they expire.

```
certavert-scan 10.0.0.0/24
```

certavert-scan connects to the machines on your network, reads the certificate each one presents (web servers, mail servers, LDAP, admin panels, appliances…) and writes a report: what is there, who issued it, and how many days it has left.

- **Runs on your machine. Nothing is sent anywhere.** No account, no key, no upload.
- **Reads every certificate**, including internal CAs, self-signed and expired ones.
- **Three files per scan**: an HTML page to read, a CSV for spreadsheets, a JSON file with everything.
- **Free and open source** (MIT), made by [CertAvert](https://certavert.com), on [PyPI](https://pypi.org/project/certavert-scan/).

> Only scan networks you own or are allowed to scan.

---

## Contents

1. [How it works](#how-it-works)
2. [Install](#install)
3. [Quick start](#quick-start)
4. [The first run](#the-first-run)
5. [The settings file](#the-settings-file)
6. [Command line](#command-line)
7. [Reading the results](#reading-the-results)
8. [Scanning regularly](#scanning-regularly)
9. [Safety and privacy](#safety-and-privacy)
10. [certavert-scan and CertAvert](#certavert-scan-and-certavert)
11. [Troubleshooting](#troubleshooting)
12. [Limits](#limits)
13. [JSON format](#json-format)
14. [Development](#development)
15. [License](#license)

---

## How it works

For each address and port it is given, certavert-scan:

1. **Opens a TCP connection.** A closed port ends here and is left out of the results.
2. **Does a TLS handshake.** When the target is a host name, the name is sent too (SNI), so a server with several sites presents the right certificate.
3. **Keeps what the server sent:** its certificate, the TLS version and the cipher.
4. **Closes the connection.** No request is made, nothing is logged in to, nothing is changed.

It doesn't check whether the certificate is trusted: internal CAs, self-signed and expired certificates are exactly what it's for. It reports what it finds instead.

When every endpoint is done, it writes the HTML, CSV and JSON files to the results folder.

By default it scans these ports, where the server speaks TLS from the first byte:

| Port | Service |
|---|---|
| 443 | HTTPS |
| 465 | SMTP over TLS |
| 636 | LDAP over TLS |
| 990 | FTP over TLS |
| 993 | IMAP over TLS |
| 995 | POP3 over TLS |
| 5986 | WinRM over HTTPS |
| 8443, 9443 | alternative HTTPS (admin panels, appliances) |

Add your own in the settings file or with `--ports`.

## Install

You need **Python 3.9 or newer**. Check with `python3 --version` (Windows: `py --version`). If you don't have it: [python.org/downloads](https://www.python.org/downloads/).

Pick your system, then **pipx** (recommended: keeps the tool apart from your other Python packages) or **pip**.

### macOS

With pipx:

```
brew install pipx
pipx ensurepath
pipx install certavert-scan
```

Open a new terminal after `pipx ensurepath`. No Homebrew? See [brew.sh](https://brew.sh), or use pip.

With pip, in a virtual environment of its own:

```
python3 -m venv ~/certavert-scan-venv
~/certavert-scan-venv/bin/pip install certavert-scan
~/certavert-scan-venv/bin/certavert-scan --version
```

### Linux

With pipx (Debian, Ubuntu; Fedora: `sudo dnf install pipx`):

```
sudo apt install pipx
pipx ensurepath
pipx install certavert-scan
```

Open a new terminal after `pipx ensurepath`.

With pip, in a virtual environment of its own:

```
python3 -m venv ~/certavert-scan-venv
~/certavert-scan-venv/bin/pip install certavert-scan
~/certavert-scan-venv/bin/certavert-scan --version
```

On Debian and Ubuntu, `python3 -m venv` needs `sudo apt install python3-venv` first.

### Windows

In PowerShell or Command Prompt, with pipx:

```
py -m pip install --user pipx
py -m pipx ensurepath
pipx install certavert-scan
```

Open a new window after `ensurepath`.

With pip:

```
py -m pip install certavert-scan
```

### After installing

pip also installs [`cryptography`](https://pypi.org/project/cryptography/), which reads the certificates, and on Python 3.9 and 3.10 [`tomli`](https://pypi.org/project/tomli/), which reads the settings file.

Check it works:

```
certavert-scan --version
```

(In a virtual environment: `~/certavert-scan-venv/bin/certavert-scan --version`.)

**Update** with `pipx upgrade certavert-scan`, or `pip install --upgrade certavert-scan` with the same pip you installed it with. **Remove** with `pipx uninstall certavert-scan`, or delete the `~/certavert-scan-venv` folder (Windows: `py -m pip uninstall certavert-scan`). The tool never updates itself.

## Quick start

Scan your network on the first run (it finds the network and asks before scanning):

```
certavert-scan
```

Or say what to scan:

```
certavert-scan 192.168.1.0/24
```

Networks, addresses and names can be mixed, each with an optional port:

```
certavert-scan 192.168.1.0/24 10.0.5.20 intranet.acme.local mail.acme.local:993
```

While it runs:

```
Scanning 254 addresses, 2,286 endpoints…
  2286/2286 checked, 14 found
Found 14 endpoints, 11 certificates: 1 expired, 2 expiring, 11 ok
  /home/jane/certavert-scan-20261023-141502.html
  /home/jane/certavert-scan-20261023-141502.csv
  /home/jane/certavert-scan-20261023-141502.json
```

Open the `.html` file in your browser.

## The first run

Run `certavert-scan` with nothing after it. With no settings file yet, it:

1. **Finds this machine's network**: the /24 around its address (`192.168.1.23` → `192.168.1.0/24`).
2. **Writes a settings file** with that network, the default ports and the current folder for the results (your home folder if the current one can't be written to).
3. **Shows the settings and asks** before scanning anything:

```
First run: wrote a settings file for this network.
Settings: /home/jane/.config/certavert-scan/certavert-scan.toml
  Targets: 192.168.1.0/24
  Ports:   443, 465, 636, 990, 993, 995, 5986, 8443, 9443
  Results: /home/jane
Scan 192.168.1.0/24 now? [y/N]
```

Answer `y` to scan now, or press Enter to stop and edit the file first. After that, `certavert-scan` alone scans with the file.

- If your network is bigger than a /24 (for example `10.0.0.0/16`), change `targets` in the file.
- If no private network is found (the machine has only a public address), the file is written with no targets: add yours.
- Run from a script (no terminal), it writes the file and stops without scanning. `--yes` scans without asking.

## The settings file

The settings file is `certavert-scan.toml`. It is looked for in this order:

1. the file given with `--config FILE`
2. `certavert-scan.toml` in the current folder
3. your own: `~/.config/certavert-scan/certavert-scan.toml` (macOS, Linux) or `%APPDATA%\certavert-scan\certavert-scan.toml` (Windows)

`--no-config` ignores all of them. `--init` writes a new one in the current folder, the same as the first run's (`--init other.toml` for another name). An existing file is never overwritten.

The file is [TOML](https://toml.io): `name = value`, `#` for comments, lists in `[ ]`, text in quotes.

```toml
# What to scan
targets = [
  "10.0.0.0/24",
  "10.0.5.0/24",
  "intranet.acme.local",
  "mail.acme.local:993",
]

# Never connect to these
exclude = ["10.0.0.1", "10.0.5.0/28"]

# Ports for targets without one
ports = [443, 465, 636, 993, 995, 8443, 9443, "9000-9010"]

# Where the files go, and which ones
output = "C:/Users/jane/scans"
formats = ["html", "csv", "json"]

# How hard to scan
workers = 16
timeout = 3
max_addresses = 65536

# What counts as Expiring, and whether to look up names
expiring_days = 45
reverse_dns = true
```

| Setting | Default | What it does |
|---|---|---|
| `targets` | (none) | Networks (`10.0.0.0/24`), addresses (`10.0.0.5`, `fd00::5`) and host names (`intranet.acme.local`), each with an optional port (`10.0.0.5:8443`, `[fd00::5]:8443`). |
| `exclude` | (none) | Addresses or networks never to connect to: printers, phones, factory or medical devices, anything fragile. |
| `ports` | the 9 ports above | Ports for targets without their own. Numbers, or ranges in quotes (`"9000-9010"`). |
| `output` | current folder | Folder for the results. `~` means your home folder. Created if missing. |
| `formats` | `["html", "csv", "json"]` | Which files to write. |
| `workers` | `32` | Connections at the same time (1–512). Lower is gentler and slower. |
| `timeout` | `3` | Seconds to wait at each step (connect, handshake). Raise it for slow links or VPNs. |
| `max_addresses` | `65536` | The scan stops before it starts if the targets add up to more addresses (a /16). Protects against typos like `10.0.0.0/8`. |
| `expiring_days` | `30` | Certificates with this many days left or fewer are Expiring. |
| `reverse_dns` | `true` | For addresses that answer, look up their name in DNS, to make results from a network easier to read. |

A misspelt setting or a wrong value stops the run with a message, so nothing is silently ignored:

```
certavert-scan: certavert-scan.toml: unknown setting 'exlude' (did you mean exclude?)
```

**The command line wins over the file.** Targets given on the command line replace the file's targets; `--exclude` adds to the file's excludes (so they're never lost by accident); any other option replaces that setting for this run.

## Command line

```
certavert-scan [TARGET ...] [options]
```

| Option | What it does |
|---|---|
| `TARGET ...` | What to scan (replaces the settings file's `targets`). |
| `-c FILE`, `--config FILE` | Use this settings file. |
| `--no-config` | Ignore every settings file. |
| `--init [FILE]` | Write a settings file for this network and stop (default `./certavert-scan.toml`). |
| `-y`, `--yes` | On the first run, scan without asking. |
| `-f FILE`, `--file FILE` | Read targets from a text file: any number per line, `#` for comments. Can be given more than once. |
| `-p PORTS`, `--ports PORTS` | Ports, e.g. `443,8443,9000-9010`. |
| `-x LIST`, `--exclude LIST` | Addresses or networks to skip, comma-separated. Can be given more than once. |
| `-o DIR`, `--output DIR` | Folder for the results. |
| `--name NAME` | File name without extension (default `certavert-scan-YYYYMMDD-HHMMSS`, so each scan has new files). |
| `--format LIST` | `html`, `csv`, `json`, comma-separated. |
| `-w N`, `--workers N` | Connections at the same time. |
| `-t SECONDS`, `--timeout SECONDS` | Seconds to wait at each step. |
| `--expiring-days N` | Days left counted as Expiring. |
| `--max-addresses N` | Largest scan allowed. |
| `--no-reverse-dns` | Don't look up names for addresses. |
| `-q`, `--quiet` | Only print errors. |
| `-V`, `--version` | Show the version. |
| `-h`, `--help` | Show the options. |

**Examples**

```
certavert-scan 10.0.0.0/24 --exclude 10.0.0.1,10.0.0.192/26
certavert-scan --file servers.txt --ports 443,8443 --output ~/scans
certavert-scan 10.0.0.0/22 --workers 8 --timeout 5
certavert-scan --config /etc/certavert-scan/office.toml --quiet
```

**Exit codes**: `0` the scan ran (whatever it found), `2` something in the input was wrong and nothing was scanned, `130` stopped with Ctrl+C.

## Reading the results

### The HTML page

One page, readable without internet. At the top: when and what was scanned, and counts (endpoints, unique certificates, each status). Then one row per endpoint, **expired and expiring first**. Type in **Filter** to show matching rows only; click a column header to sort by it. It follows your computer's light or dark setting.

| Column | |
|---|---|
| Status | see below |
| Days left | whole days until the certificate ends, rounded down; negative once expired |
| Endpoint | name or address and port; below it the address, or the name from DNS |
| Name | the certificate's common name, and the names it is valid for (SANs) |
| Issuer | who signed it (hover for the full name); "(self-signed)" if it signed itself |
| Expires | the end date |
| TLS | the protocol version the server chose |
| Key | key type and size |
| Issues | problems besides the dates (see below) |

### Status

| Status | Meaning |
|---|---|
| **Expired** | Past its end date. |
| **Expiring** | `expiring_days` (30) days left or fewer. |
| **OK** | More than that left. |
| **Not yet valid** | Its start date is in the future (often a wrong clock somewhere). |
| **Error** | Something answers but no certificate could be read: not TLS, the handshake failed, or the name isn't in DNS. Also a port you asked for by number (`host:8443`) that is closed. |

The status comes from the dates only. A certificate can be OK and still have issues.

### Issues

| Issue | Meaning |
|---|---|
| Self-signed | The certificate signed itself. Normal for some appliances; browsers warn about it. |
| Name not in certificate | The host name you scanned isn't among the certificate's names, so clients connecting by that name will warn. Only checked when you scan by name. |
| Old protocol (TLSv1) | The server chose TLS 1.0 or 1.1 (or SSLv3). Browsers dropped them in 2020. |
| Weak signature | Signed with SHA-1 or MD5. |
| Small key (RSA 1024) | An RSA key under 2048 bits. |

### The CSV file

One row per endpoint, UTF-8 (opens in Excel, Numbers, LibreOffice and Google Sheets). Columns: Status, Days left, Endpoint, Address, Port, Name, Reverse DNS, Common name, SANs, Issuer, Self-signed, Not before, Not after, TLS version, Cipher, Key, Signature, Serial, SHA-256, Issues, Error. Dates are UTC.

### The JSON file

Everything, including each certificate in PEM, for scripts and other tools. See [JSON format](#json-format).

## Scanning regularly

Certificates are easiest to renew before they expire, and new ones appear as servers are added. Run the scan on a schedule: monthly is enough for most networks, weekly for large or busy ones. Each run writes new files named by date and time, so you can compare one month with the next.

### Before you schedule it

1. **Have a settings file.** A scheduled run has no one to answer questions, so it never does the first-run setup: it writes the file and stops. Run `certavert-scan` once by hand (or `certavert-scan --init` in a folder of your choice) and check `targets`, `exclude` and `output`.
2. **Set `output` to a full path**, such as `/home/jane/scans` or `C:/Users/jane/scans`. A scheduled job doesn't start in the folder you'd expect.
3. **Find the full path of the command.** Schedulers don't search your PATH the way a terminal does:
   - macOS, Linux: `which certavert-scan` → e.g. `/home/jane/.local/bin/certavert-scan`
   - Windows: `where.exe certavert-scan` → e.g. `C:\Users\jane\AppData\Local\Programs\Python\Python312\Scripts\certavert-scan.exe`
4. **Run the exact command once by hand** to see that it works:

```
/home/jane/.local/bin/certavert-scan --quiet
```

`--quiet` prints only errors, so the scheduler stays quiet unless something goes wrong.

### Linux and macOS: cron

Open your crontab (it runs as you, so it finds your own settings file):

```
crontab -e
```

Add one line. The five fields are minute, hour, day of month, month, day of week:

```
# 07:00 on the 1st of every month
0 7 1 * * /home/jane/.local/bin/certavert-scan --quiet

# 07:00 every Monday
0 7 * * 1 /home/jane/.local/bin/certavert-scan --quiet

# 07:00 every Monday, with a specific settings file
0 7 * * 1 /home/jane/.local/bin/certavert-scan --config /home/jane/office.toml --quiet
```

Save and close the editor. `crontab -l` shows what is scheduled.

**Keep a log** of each run (errors included) by adding this to the end of the line:

```
>> /home/jane/scans/cron.log 2>&1
```

**Get an email when something fails**: cron mails anything a job prints to the address in `MAILTO`, if the machine can send mail. Put this line above the job:

```
MAILTO=jane@example.com
```

**Delete scans older than a year** with a second line, on the 2nd of each month:

```
0 7 2 * * find /home/jane/scans -name 'certavert-scan-*' -mtime +365 -delete
```

**macOS note**: if `output` is in Documents, Desktop or Downloads, macOS blocks cron from writing there. Use another folder (such as `~/scans`), or give `cron` Full Disk Access in System Settings → Privacy & Security.

### Linux: systemd timer

If you prefer systemd to cron, create two files in `~/.config/systemd/user/`.

`certavert-scan.service`:

```
[Unit]
Description=certavert-scan

[Service]
Type=oneshot
ExecStart=%h/.local/bin/certavert-scan --quiet
```

`certavert-scan.timer`:

```
[Unit]
Description=Run certavert-scan monthly

[Timer]
OnCalendar=monthly
Persistent=true

[Install]
WantedBy=timers.target
```

Then:

```
systemctl --user daemon-reload
systemctl --user enable --now certavert-scan.timer
systemctl --user list-timers
```

`Persistent=true` runs a missed scan as soon as the machine is back on. `journalctl --user -u certavert-scan` shows the output. To run while you're logged out: `loginctl enable-linger $USER`.

### Windows: Task Scheduler

**With the window:**

1. Open **Task Scheduler** → **Create Basic Task**.
2. Name: `certavert-scan`. Trigger: **Monthly** (or Weekly), pick the day and time.
3. Action: **Start a program**.
   - Program: the full path from `where.exe certavert-scan`
   - Arguments: `--quiet`
   - Start in: your results folder, e.g. `C:\Users\jane\scans`
4. Finish. To run it while you're logged out: open the task's **Properties** → **Run whether user is logged on or not**.

Right-click the task → **Run** to test it now; **Last Run Result** should say `0x0`.

**With PowerShell**, weekly on Mondays at 7:00:

```
$exe = (Get-Command certavert-scan).Source
$action = New-ScheduledTaskAction -Execute $exe -Argument "--quiet" -WorkingDirectory "$HOME\scans"
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 7am
Register-ScheduledTask -TaskName "certavert-scan" -Action $action -Trigger $trigger
```

Monthly instead: in the window, change the trigger in the task's **Properties** → **Triggers** (PowerShell's `New-ScheduledTaskTrigger` has no monthly option).

**Delete scans older than a year** (PowerShell):

```
Get-ChildItem "$HOME\scans\certavert-scan-*" | Where-Object LastWriteTime -lt (Get-Date).AddYears(-1) | Remove-Item
```

### What a scheduled run does

- It uses the settings file: `--config` if given, else `certavert-scan.toml` in the folder it starts in, else your own.
- With no settings file, its first run writes one for the machine's network and stops without scanning; the next run scans with that file. Check the file before then.
- It writes new files each run and never deletes old ones.
- Exit code `0` means the scan ran (whatever it found); `2` means the settings are wrong and nothing was scanned. The scheduler shows the code (cron mails the error message).

## Safety and privacy

**What it does on your network**

- One TCP connection and one TLS handshake per endpoint, then the connection is closed.
- No requests, no logins, no password guessing, no vulnerability tests.
- 32 connections at a time by default. Use a lower `workers` and `exclude` for fragile devices.
- It may show up in your intrusion detection or firewall logs as a port scan. **Tell your security team before scanning.**

**What it does with the results**

- Writes files on your machine. That's all.
- **It never contacts CertAvert** or anyone else, has no telemetry, and never updates itself. The only machines it talks to are the ones you scan, and your DNS server for names.
- It only reads what servers send to anyone who connects. It never sees or asks for private keys.

**The results file is a map of your network** (addresses, names, services). Keep it like other internal documents.

## certavert-scan and CertAvert

certavert-scan is made by [CertAvert](https://certavert.com) and is free to use, change and share under the MIT license. **It works on its own: no CertAvert account is needed and it never connects to certavert.com.**

The two cover different sides:

| | certavert-scan | CertAvert |
|---|---|---|
| What | the certificates **inside** your network | your **public** sites and services |
| How | you run it, when you want | checks them for you, around the clock |
| Results | files on your machine | a dashboard, and email alerts before anything expires |
| Cost | free | free plan, paid plans for more |

The only link between them is a line at the bottom of the HTML page, linking to certavert.com.

## Troubleshooting

**`certavert-scan: command not found`** (or "not recognized" on Windows)
pip installed it in a folder that isn't on your PATH. Use `pipx ensurepath` and open a new terminal, or run it as `python3 -m certavert_scan` (Windows: `py -m certavert_scan`).

**`Failed building wheel for cryptography`** (or `maturin failed`, `cargo`)
pip found no ready-made build of `cryptography` for your machine and tried to compile it. Update pip (`python3 -m pip install --upgrade pip`) and install again. On an Intel Mac, certavert-scan 0.1.1 and later pick a `cryptography` version that has a build for it; with 0.1.0, run `pip install "cryptography<49"` first. On **Windows on ARM** (Surface, Snapdragon laptops) there is no build for the ARM Python: install the 64-bit (x64) Python from python.org instead; it runs there too.

**`error: externally-managed-environment`**
Your system's Python doesn't let pip install into it (Homebrew on macOS, Debian 12, Ubuntu 23.04 and later). Use pipx or a virtual environment, as in [Install](#install).

**Found 0 endpoints, but there are servers**
- A firewall between you and them drops the connections. Scan from inside the same network, or ask for the ports to be opened from the scanning machine.
- The services are on other ports: add them (`--ports 443,8443,10443`).
- Over a VPN or slow link, raise `--timeout` to 5 or 10.

**A server shows the wrong certificate**
Servers with several sites send their default certificate when asked by address. Scan by name: `certavert-scan intranet.acme.local`.

**"Not TLS, or the TLS handshake failed"**
Something answers on that port but doesn't speak TLS from the first byte: a plain web server, SSH, or a service that starts in plain text and switches with STARTTLS (see [Limits](#limits)).

**The scan is slow**
Most time goes to ports that drop connections without answering: each one waits `timeout` seconds. Scan fewer ports, raise `workers` (try 64), or lower `timeout` to 1–2 on a fast local network.

**"is more than the limit of 65,536"**
The targets add up to more than a /16. Check for a typo; if you really mean it, raise `max_addresses` or use `--max-addresses`.

**"could not write the files"**
The results folder isn't writable. Choose another with `--output` or `output`.

## Limits

- **STARTTLS isn't read yet**: SMTP on 25/587, IMAP on 143, POP3 on 110, LDAP on 389, FTP on 21, PostgreSQL, MySQL. Nor is RDP on 3389. Their certificates are not listed.
- **Not checked against a trust store**: the tool shows who issued each certificate but doesn't say whether your computers trust that issuer.
- **The rest of the chain** (intermediate certificates) is included only on Python 3.13 and newer.
- **Revocation** is not checked.
- **The first run** guesses a /24. Larger networks need the settings file changed.

## JSON format

```json
{
  "format": "certavert-scan",
  "format_version": 1,
  "tool_version": "0.1.2",
  "scan": {
    "started_at": "2026-10-23T14:15:02Z",
    "finished_at": "2026-10-23T14:16:40Z",
    "targets": ["10.0.0.0/24", "intranet.acme.local"],
    "targets_text": "10.0.0.0/24, intranet.acme.local",
    "ports": [443, 8443],
    "ports_text": "443,8443",
    "excluded": ["10.0.0.1/32"],
    "expiring_days": 30
  },
  "summary": { "endpoints": 12, "certificates": 9, "Expired": 1, "Error": 1, "Not yet valid": 0, "Expiring": 2, "OK": 8 },
  "endpoints": [
    {
      "endpoint": "intranet.acme.local:443",
      "address": "10.0.0.5",
      "port": 443,
      "name": "intranet.acme.local",
      "reverse_dns": null,
      "status": "Expiring",
      "error": null,
      "tls_version": "TLSv1.3",
      "cipher": "TLS_AES_256_GCM_SHA384",
      "issues": [],
      "certificate": {
        "subject": "CN=intranet.acme.local",
        "common_name": "intranet.acme.local",
        "organization": null,
        "sans": ["intranet.acme.local"],
        "issuer": "CN=Acme Internal CA,O=Acme",
        "issuer_common_name": "Acme Internal CA",
        "issuer_organization": "Acme",
        "self_signed": false,
        "is_ca": false,
        "not_before": "2026-01-10T00:00:00Z",
        "not_after": "2026-11-12T00:00:00Z",
        "days_left": 19,
        "not_yet_valid": false,
        "serial": "4F2A…",
        "sha256": "9C1E…",
        "key_type": "RSA",
        "key_bits": 2048,
        "signature": "sha256WithRSAEncryption",
        "pem": "-----BEGIN CERTIFICATE-----\n…"
      },
      "chain": []
    }
  ]
}
```

- Times are UTC (`Z`). `days_left` is whole days, rounded down, at the start of the scan.
- `endpoints` are sorted as in the HTML page. An endpoint with `"status": "Error"` has `"certificate": null` and the reason in `error`.
- `chain` holds the other certificates the server sent, in PEM (Python 3.13 and newer; empty before).
- `serial` and `sha256` are uppercase hexadecimal.
- `format_version` changes only when a field changes meaning or goes away. New fields can appear in any version: ignore the ones you don't know.

## Development

```
git clone https://github.com/certavert/certavert-scan.git
cd certavert-scan
python3 -m pip install cryptography
PYTHONPATH=src python3 -m certavert_scan --help
PYTHONPATH=src python3 -m unittest discover -s tests -t .
```

The tests start small TLS servers on 127.0.0.1 with made-up certificates; they never touch your network or the internet.

| File | What it does |
|---|---|
| `src/certavert_scan/cli.py` | the command line and the run itself (start reading here) |
| `src/certavert_scan/config.py` | the settings file: finding it, reading it, writing the first one |
| `src/certavert_scan/targets.py` | turns targets into addresses and ports |
| `src/certavert_scan/probe.py` | connects to one endpoint and reads its certificate |
| `src/certavert_scan/certinfo.py` | turns a certificate into readable fields |
| `src/certavert_scan/output.py` | writes the HTML, CSV and JSON files |
| `tests/` | the tests |

Bug reports and pull requests are welcome.

## License

MIT, see [LICENSE](LICENSE). Made by [CertAvert](https://certavert.com).
