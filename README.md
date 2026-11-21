# Prahari · प्रहरी — 1.37.2

*Your network's 24x7 guard*


A network operations console for a small or mid-size office that runs on one PC, on
your own network, with no cloud account and no agent on the devices. It answers four
questions in one place:

1. **What is on my network?** — router, switch, access points, KOT/receipt printers,
   printers, scanners, DVR/NVR, cameras, servers, phones — with the evidence for each verdict.
2. **Is it healthy right now?** — every device polled continuously, up/degraded/down with
   latency and packet loss, an incident when something stays broken, and a diagnosis that
   says what to do next.
3. **What are my IP addresses?** — public IP with ISP, local IP, subnet, gateway, DNS.
4. **Who is eating the internet?** — per-device download/upload and data used today, from
   NetFlow/sFlow exported by your router (or SNMP counters, or packet capture).

Windows 10/11 and Server; also runs on Linux/macOS.

![Overview](screenshot.png)

---

## What's new in 1.37.2 — security fix

- The certificate-renewal command (Settings -> Certificates) no longer runs through a command shell. It is split into
  the program and its arguments, and shell syntax (`` ; | & < > $ ` % ^ ``) is refused when you save it and when it
  runs. Before, anyone who could change that setting could chain other commands onto it, and Prahari runs as SYSTEM.
- LIMITS.md section 5 now has a security review: what holds, and where Prahari could be compromised, worst first.

## What's new in 1.37.1 — no more false "Network is congested"

- "Network is congested" now needs at least two always-on devices slow at the same time (or the gateway / internet
  slow as well). Switched-off devices no longer count, and printers, scanners, phones and IoT devices - which answer
  slowly when they wake from power-save - never make a congestion verdict on their own. A single slow printer is
  now reported as "<printer> is degraded" (low severity).
- Reports to the Prahari portal now include what the updater is doing (installing, restarting, or the error that
  stopped it), so the portal can show whether an update went in.

## What's new in 1.37.0 — escalation, ready-made sensors, config backup

- **Escalation** (Settings → Escalation): if an incident or a down sensor is still open after the minutes you set,
  the next people are told by email, phone push or Telegram, once per step, with a cap per problem and quiet hours
  (only critical/high problems page at night). Every page is written into the incident's timeline.
- **Ready-made sensors** (Sensors → Ready-made sensors): booking page, PMS port, guest-portal certificate, UPS battery,
  server free disk, core switch, invoices in the last hour - pick one, change the target, add it.
- **Two new sensor types:** `wmi` (a Windows counter or WMI count on this PC, e.g. free disk space) and `sqlite`
  (one read-only SELECT against a database file, e.g. "invoices in the last hour").
- **Configuration backup** (Settings → Configuration backup): every N hours Prahari copies the running configuration
  of the switches, routers and firewalls you list (Cisco, Aruba, HP, D-Link, TP-Link, Juniper, MikroTik, Ubiquiti,
  Fortinet, pfSense, Linux) over key-based SSH with one fixed read-only command, keeps 30 dated copies, and emails the
  exact lines that changed. Private LAN addresses only. Sophos is not supported over SSH (its console is a menu) - use
  Sophos's own scheduled backup. Also `Prahari.exe --config-backup`.

## What's new in 1.36.1

- Remote access setup reports its progress and any error to the Prahari portal, waits for the Tailscale service after
  installing, retries joining, and tries again every 10 minutes.

## What's new in 1.36.0

- Remote access from anywhere: once your organisation's Tailscale key is saved on the Prahari portal, Prahari installs
  Tailscale at each location by itself, joins, and shares that office's network - so the portal's Open / RDP / SSH
  buttons reach every device from your laptop or phone.

## What's new in 1.35.0

- Both internet lines of a dual-WAN firewall are shown on the portal, each with its up/down state, read from the
  firewall over SNMP - including the idle backup line. You are emailed when a line goes down or comes back.
- Settings has a field for the SNMP community of your firewall and switches.
- Fixed: reading router and switch interfaces over SNMP never worked (a missing name), so per-port traffic was missing.

## What's new in 1.34.3

- New logo - an eye watching the network - for Prahari.exe, the desktop icon, the dashboard and its browser tab
  (was a plain green dot). Source: prahari-logo.svg.

## What's new in 1.34.2

- Prahari.exe now always runs in the background on Windows - no question. Started without administrator rights,
  it asks Windows for them (the usual "Allow this app to make changes?" - choose Yes). The console window then closes by itself.
- Use --foreground to keep Prahari in a window only.

## What's new in 1.34.1

- A "Prahari" icon on the desktop (shared by every user) opens the dashboard; created with background mode, and
  by the background copy at start for installs set up earlier.
- Fixed: reports to the Prahari portal did not name the Prahari version, so the portal could not show it or offer an update.

## What's new in 1.34.0 — keeps running when the window is closed

- On first start (Windows) Prahari asks "Run in the background?". Yes (as administrator) registers a Windows task
  that starts Prahari at boot as SYSTEM - no window, nobody needs to be logged in, no 3-day time limit, restarted
  within a minute if it stops - using the same data (organisation key, users, settings) via --home.
  The program is copied to C:\ProgramData\Prahari so moving the download does not break it.
- Starting Prahari.exe again while it runs in the background just points to the dashboard (no second copy).
- Manual control, as administrator: Prahari.exe --install-service / --remove-service.

## What's new in 1.33.1 — a lighter dashboard

- The dashboard refreshes every 5 s instead of 3 s, and not at all while its tab is hidden or minimised.
- Its answers are compressed: about 14 KB per refresh instead of ~600 KB for 150 devices (~0.2 MB a minute
  instead of ~13 MB).
- The device sparkline uses the last 30 polls (the device drawer still loads the full history).
- Reports to the Prahari portal carry the full device list only when a device appears, disappears or changes
  state, and at least every 5 minutes; other reports are about 0.5 KB.

## What's new in 1.33.0 — the whole dashboard on the Prahari portal

- Reports to the Prahari portal now carry every device (name, IP, type, maker, state, latency, loss, open ports, MAC),
  every open incident and the top 10 traffic users, so a location's full detail can be opened on the portal from anywhere.
- Settings: one "Prahari portal" card (connected or not, last report, organisation key, Disconnect). The head-office
  hub for a local network moved under Advanced; its Fleet update card shows only on a hub.
- Overview shows the portal connection in one line. Reporting starts at once, not after the first scan.
- Each installation has an id, so the portal can warn when two Praharis report under the same location name.
- Only one Prahari per network: the portal recognises a network by its router and refuses a second Prahari there.
  The second one goes into standby (no scanning, no alerts, a clear message in the console and dashboard) and takes
  over by itself if the first one stops reporting for 15 minutes. Different locations may use the same IP range
  (e.g. both 192.168.0.x) - they have different routers.

## What's new in 1.32.3 — connect to the portal when Prahari first starts

- First start in a console window: Prahari asks for the organisation key from the Prahari portal (Enter skips)
  and the name of the site,
  and connects straight away - while the dashboard is already running.
- Until the site is connected, the dashboard's Overview shows a "Connect to the Prahari portal" box
  (site name + token + Connect, or Not now).
- Sites connected to the portal can be updated from the portal (Update / Update all); each site still installs
  only a signed release, verified on the site.

## What's new in 1.32.2 — Settings keeps what you type

- Fixed: the dashboard refreshes every 3 seconds, and that redraw wiped anything typed or pasted in Settings
  (or any other form) before it could be saved - a pasted hub token simply vanished. The refresh now waits
  while you are editing; saving, or switching tabs, shows the fresh data.
- Watching a site on the Prahari portal is now: paste the portal token (psk_...) in Settings -> This site reports
  to a hub, and Save settings. No Hub URL, no rescan or restart - reporting starts on Save.

## What's new in 1.32.1 — the dashboard is easy to find

- The console window now shows a clear **DASHBOARD** box with the address to open (and the LAN address when shared).
  On Windows Server, where Edge or Chrome is often missing, nothing opened by itself and the console looked like all there was.
- If no browser window can be opened, the console says so and repeats the address.
- Chrome or Edge installed for the current user only (`%LOCALAPPDATA%`) is now found too.
- (1.32.0 was a copy that was never published; 1.32.1 follows 1.31.0 directly.)

## What's new in 1.31 — sensor history, charts and a wall map

From the parallel Prahari copy's 1.31, reviewed, fixed and tested:

| Feature | What it does |
|---|---|
| **Sensor history** | Every check is saved, kept for 30 days (cleaned up daily), so the trend survives a restart. Each row shows the last 30 checks as a colour strip; click a sensor for **24-hour, 7-day and 30-day** charts with the availability percentage. |
| **Two more sensor types** | `service` (a Windows service via `sc query`, or a systemd unit) and `proc` (a running process). The name is passed as an argument, never through a shell. |
| **Wall map** | A tab for the office TV: big colour tiles, one per hotel on the hub or one per *monitored* device on a site (a laptop that is only listed is not shown as down), refreshing every 3 s, with a full-screen button. |
| **One broken panel no longer blanks the console** | A view that fails shows its error in that panel; the rest keeps working. |

Fixed while merging: sensor history was never cleaned up (the 30-day promise did not hold), a bad `hours=` value crashed the history request, and the Wall map painted every unmonitored device red.

## What was new in 1.30 — service checks, quiet hours, dependencies

From the parallel Prahari copy's 1.29 and 1.30, reviewed, fixed and tested:

| Feature | What it does |
|---|---|
| **Sensors** (new tab) | Checks you define: **http** (expect a status and a word on the page), **tcp**, **dns** (expect an address), **cert** (days until a certificate expires — also for devices with their own self-signed certificate), **snmp** (a value against a threshold — UPS battery, temperature), **ping**. Each has its own interval and limits, a short history, and alerts when it goes down *or* into warning, including when it is already failing on its first check. Sensors run in their own thread, so a slow website never delays the device checks. |
| **Quiet hours** | Maintenance windows (`match | YYYY-MM-DD HH:MM | YYYY-MM-DD HH:MM | reason`) silence a device or a sensor without switching monitoring off — the event log still records what happened. A mistyped date is refused, not silently ignored. |
| **Dependencies** | `child_ip = parent_ip`: when the switch is down, the printer behind it does not raise its own incident — one alert instead of a cascade, and it chains (a device behind the printer is quiet too). Removing a line really removes the dependency. |
| **Device links** | `#device=192.168.1.5` in the address opens that device's panel directly; "last seen" shows a relative time. |

| **Serve updates from the head office** | Settings → *Fleet update* → **Publish to branches**: the hub fetches the newest signed release from GitHub (or reads it from a folder, for an offline head office), **verifies the signature and every checksum**, and serves that exact copy to its branches — so hotels never need to reach GitHub. Branches download it with their branch token and verify the signature **again** with the key built into Prahari before installing. The hub decides *when*; it cannot change *what*: a file altered on the hub is refused by every branch. (This replaces the parallel copy's unsigned "publish a zip" — same convenience, without letting whoever controls the hub run code on every hotel.) |

## What was new in 1.29 — NetSentinel is now Prahari

**Prahari** (प्रहरी) is Sanskrit for *watchman, one who keeps watch* — the same idea as "sentinel",
in a word that reads naturally in an Indian office or hotel. The dashboard, sign-in page, emails,
PDF reports, phone app, installer, shortcuts and the exe (`Prahari.exe`) all carry the new name.

Nothing is lost on the way:

| Kept as it was | Why |
|---|---|
| Data folder `~/.netsentinel` (history, settings, users, backups) | an existing install keeps everything |
| Program file `netsentinel.py` and the `netscan` package | installed copies only accept updates with file names they know; `prahari.py` is a launcher with the new name |
| GitHub repository `RavindraBellur/NetSentinel` | it is where every installed copy looks for signed updates |

Copies running NetSentinel 1.18–1.28 update to Prahari by themselves like any other release (an
existing `NetSentinel.exe` keeps its file name). Running the new setup on a PC that has a
NetSentinel install upgrades that folder in place and removes the old auto-start task, firewall
rules and desktop shortcut, so the two never run side by side.

To rebrand again later: `python3 rename.py --name "Netra" --devanagari "नेत्र" --tagline "the eye on your network"`.

## What was new in 1.28 — UDP services found, and a fuller port catalogue

| Change | What it does |
|---|---|
| **UDP services are now probed** | Every device is asked, with a real request, whether it runs **NTP (123)**, **NetBIOS (137)**, **SNMP (161)**, **UPnP (1900)** and **mDNS (5353)**. A port counts as open only when the service answers — silence never does. UPnP on a camera or recorder is graded **high**, and its SERVER header (often the vendor and model) is shown and used to identify the device. |
| **Switches and APs identified over SNMP again** | SNMP and NetBIOS are UDP, so they were never in the TCP scan — and the identification step waited for them there. Result: only the gateway was ever identified over SNMP, and Windows names over NetBIOS never were. Both now work for every device. |
| **Your SNMP communities are used** | The community names in Settings → Discovery are tried first (they were ignored), all at once — about 1 s per device instead of 5.6 s. |
| **Mail ports scanned** | SMTP 25, submission 587, IMAPS 993, POP3S 995 are now in the TCP scan. |
| **Port catalogue: 49 services** | From the parallel Prahari copy's 1.28: RTSP 554 (high — cameras often stream without a password), IPP 631, recorder web ports 8000/8081/8888/9000, and the services above, each with why it matters, how to close it and when it is legitimate. |

Not probed: NetBIOS datagram (138) does not answer requests, so it cannot be detected from outside;
SNMPv3-only devices answer only with SNMPv3 credentials (Settings → SNMPv3).

## What was new in 1.27 — Windows sign-in, Update now, known limits

| Change | What it does |
|---|---|
| **Sign in with Windows** | Sign-in is now always required, on the PC itself too. Use your normal Windows account and password (`ravi`, `OFFICE\ravi` or `ravi@domain`) — Windows checks the password, Prahari never stores it. Administrators of the PC get admin rights; other Windows users are refused unless Settings allows them Viewer or Engineer. Prahari's own accounts keep working. Proven on the build machine against a real administrator and a real standard account. |
| **Lockout that actually locks** | After five wrong passwords the sign-in form now refuses the next attempt *before* checking it — before, the counter only changed the message and guessing could continue. |
| **Update now** | When a signed new version is out, admins see **Update now to x.y.z** in the header: confirm, it installs, restarts and reloads by itself. If the new version does not start, the current one is put back. |
| **Known limits** | Settings → *Known limits*, `/limits.md`, or `run.bat --limits`: what is proven and how, what has never run on real equipment, and what is not built. Shipped as `LIMITS.md`. |

## What was new in 1.26 — Claude diagnosis, safety rails, and proof

| Change | What it does |
|---|---|
| **Claude AI diagnosis** | When an incident opens or escalates, the built-in rules diagnose it and the alert goes out at once; in the background Claude (claude-opus-5-5 by default) reads the same evidence — device, neighbours, gateway, internet targets, recent events, traffic, and the rules' own verdict — and replaces the diagnosis with a structured one: root cause, confidence, evidence, alternatives, impact, ordered steps, missing data. If Claude is unavailable for any reason the rule-based diagnosis stays. Settings → *Claude AI diagnosis*: your own Anthropic API key, model, effort, hourly limit, *Test the key*. |
| **Ask AI** | A header button opens a chat about the live network ("why is the internet slow at reception?"). Answers use only the data that user is allowed to see. |
| **Safety rails for active features** | The factory-password check and PoE power-cycling refuse any address outside private LAN ranges, whatever the allow-list says; switching either on records who did it and when (shown in Settings and the Events log); power-cycling stays dry-run until explicitly set live. The EULA now spells out the operator's responsibility. |
| **Secrets never reach the browser** | Telegram token, SNMPv3 passwords, SSO client secret, push URL and AI key are masked for every user (viewers used to receive some of them), and a masked value can never overwrite the real one. The AI key is encrypted at rest with the other secrets. |
| **Proof: 40 automated tests, run on Windows before every build** | Signed updates (bad signature, tampering, path traversal, rollback, hub fleet update), Claude diagnosis with a fake API (fallback on refusal/errors/limits), factory-password checks against fake devices, backup restore with live WAL data, SNMPv3 RFC 3414 vectors, the SLA PDF, and the live console (no secrets in the API, CSRF guard, valid dashboard JavaScript). The build then proves the real `Prahari.exe` replaces itself while running and refuses a tampered release. A failing test stops the release. Run them yourself: `python -m unittest discover -s tests -t .` |
| **scapy no longer bundled in the exe** | scapy is GPL-2.0; it stays available for source installs (packet capture) but is never shipped inside Prahari.exe, and the build fails if it ever is. |

## What was new in 1.25 — the housekeeping that protects what you already have

| Feature | What it does |
|---|---|
| **Restore a backup** | `run.bat --backups` lists them, `run.bat --restore <file> --confirm` puts one back. Recent changes are flushed into the database first, the live database is copied aside with SQLite's backup API, and rolled back automatically if the restored file fails its integrity check. A backup you have never restored from is a hope, not a backup. |
| **Monthly report by email** | On the 1st at 07:00 (configurable) the previous month's PDF is built and mailed to the owners — attachment included, last-send recorded so a restart cannot send it twice. |
| **Fleet SLA** | Branches now include a rolling 31-day summary in every report; the hub turns those into **one PDF per hotel**. Reports → *All hotels (hub)*, or `run.bat --sla-fleet reports`. |

## What was new in 1.24 — factory passwords, found safely

| Feature | What it does |
|---|---|
| **Factory-password check** | Tries a short list of *published* factory logins (admin/admin, admin/12345, root/root, ubnt/ubnt …) once each against devices on the allow-list, and reports the ones that still work: "Lobby camera still accepts the factory login admin/12345 on port 8080". Before guessing, it confirms the device actually demands a password (a page that opens without one is never reported as a factory login). Opt-in, needs an explicit "I own this network" confirmation, a per-device attempt cap and a pause between tries. |

What it checks, and what it deliberately does **not** do, is spelled out in section 3b5.

## What was new in 1.23 — topology, SLA report, exposure, guarded fixes, secrets at rest

Everything below (the 1.22 and 1.23 work done in the parallel copy) arrives in Prahari as 1.23.

### Exposure, guarded fixes and secrets at rest

| Feature | What it does |
|---|---|
| **Open-port exposure + hardening plan** | Every open port on every device, graded, with **the exact steps to close it** — Windows, Linux, router, or the device's own admin page — plus when it is legitimate to keep. New **Exposure** tab; click a row for the fix; **Download the hardening plan (Markdown)** for the technician. |
| **Guarded auto-remediation** | *(As of 1.26 the guarded action exists but nothing triggers it automatically yet.)* One action only: power-cycle the PoE port an AP or camera hangs off. It runs only when remediation is on, the device is on the allow-list, it is inside the maintenance window, and under the hourly limit — with **dry-run on by default**. Every attempt, refused or executed, lands in Events. |
| **Secrets encrypted at rest** | SMTP password, Telegram token, SNMPv3 keys, SSO secret and webhook URL are stored as `enc:v1:` AES-GCM blobs with a 0600 key file beside the database. Old plain-text values keep working. |
| **Installable console (PWA)** | Manifest, service worker and icons: "Add to Home screen" on a phone gives a full-screen app that still opens when the link is flaky; live data is never cached. |

### A map, and a report you can hand over

| Feature | What it does |
|---|---|
| **Topology map** | Walks LLDP (IEEE 802.1AB) and CDP on every switch and AP, merges the two, drops duplicates, and lays the building out by depth from the gateway. Shows which port connects to what, marks neighbours that have no IP in the scan, and clicking a box opens the device. Rebuilt every ten minutes. |
| **Monthly SLA report (PDF)** | One command or one button: `run.bat --sla-report "Udaipur - Lake Road" --sla-month 2026-11`, or Reports → *Last month (PDF)*. Availability, devices, incidents, MTTR, longest outage, per-device uptime/latency/p95/loss, disk trends, Wi-Fi retry rates, plus a page explaining exactly how each number was measured. |

The PDF is written by a small built-in writer (no reportlab, no pip), so it works on a hotel
PC that has never installed anything.

## What was new in 1.22 — one line again: 1.21 features + signed auto-update

1.19–1.21 were developed in a parallel copy; 1.18 added signed automatic updates.
1.22 brings both together under the Prahari name, so every install — including 1.18 —
updates itself to it.

| Change | Why |
|---|---|
| **Everything from 1.19, 1.20 and 1.21** | Anomaly detection, capacity forecasting, ntfy phone alerts, security posture, nightly database backup, per-site role scoping, Telegram bot, SNMPv3, Wi-Fi health. |
| **Fleet update now uses signed releases** | The hub only says *which version* the branches should run (Settings → *Fleet update*); each branch installs the newest release signed with the Prahari key. Before, the hub supplied a URL and hash itself, so anyone with access to the hub could run code on every branch — and it could not update the single-file exe at all. |
| **Fixes** | `--agent` no longer crashes on start; Windows batch files have Windows line endings again; the GitHub build works. |

## What was new in 1.21 — SNMPv3 and real Wi-Fi health

| Feature | What it does |
|---|---|
| **SNMPv3 (USM)** | Auth HMAC-MD5/SHA-1/SHA-256/SHA-512, privacy AES-128-CFB, automatic engine discovery, key localisation per RFC 3414. **Verified against the RFC 3414 A.3 test vectors** (`maplesyrup` → the published Ku values) and against a mock agent for the full encrypted handshake. Community strings stop crossing the wire. |
| **Wi-Fi health** | Standard IEEE802dot11 counters per radio give **retry rate** and **failure rate** — the numbers that match what guests complain about. Above 10% retries a radio is "fair", above 25% "poor", and the Overview says so. Works on any AP that speaks SNMP. |

## What was new in 1.20 — safe to run a hundred of them

| Feature | What it does |
|---|---|
| **Nightly database backup** | A consistent copy of the SQLite file every 24 h (SQLite backup API, so it is safe while running), verified with `integrity_check`, keeping 7 daily + 4 weekly copies. Settings → *Database backup*, plus a **Back up now** button. |
| **Fleet update** | The hub tells branches which version to run. *(Since 1.22 branches install only signed releases — see above.)* |
| **Per-site role scoping** | A user can be tied to named locations. A hotel GM signs in and sees only their property — no corporate devices, traffic or incidents — with a line saying so. Admins see everything. |
| **Telegram bot** | `/status`, `/incidents`, `/ack INC-…`, `/sites` from your phone. Only chat ids you list may use it; anyone else is told their id so you can add it deliberately. |

## What was new in 1.19 — it predicts, and it grades security

| Feature | What it does |
|---|---|
| **Anomaly detection** | A mean and spread per device **per hour of day** (14 days, EWMA). A reading is flagged only when it is both unusual for that hour *and* materially bad — "Kitchen AP: latency 90 ms is 6.7σ above the usual 5 ms for this hour". Every alert carries the baseline it was compared against. |
| **Capacity forecasting** | A straight line through the last 14 days of agent samples: "disk on BILLING-SRV is 88% and rising 1.2%/day — full in about 10 days", severity rising as the date approaches. |
| **Phone alerts (ntfy.sh)** | Free push to your phone: install the ntfy app, pick a topic, done. No account, no SMS bill, no per-message cost. Also posts to any custom webhook. |
| **Security posture** | Grades what the scan already saw: Telnet open, admin page on plain HTTP, default SNMP community, CCTV recorder with a web admin page, RDP/SMB/FTP exposed — plus the console itself (no TLS, no allow-list, no 2FA, no heartbeat). Each finding carries a one-line fix, and the network gets a score out of 100. |

## What was new in 1.18 — it updates itself

| Change | What it does |
|---|---|
| **Automatic updates** | Every 6 hours Prahari checks the newest published release on GitHub. A newer, correctly signed version is downloaded, installed and started on its own; the console is back in under a minute. |
| **Signed releases only** | `latest.json` is signed (Ed25519) on the publisher's PC and pins the SHA-256 of every file. A release without a valid signature, or a file that doesn't match, is never installed. Needs the `cryptography` package (bundled in the exe). |
| **Automatic rollback** | The old version waits 25 seconds after handing over; if the new one stops, the old one is put back. A version that fails to come up three times in a row is also rolled back, and skipped from then on. |
| **Settings → Updates** | Current and newest version, last check, *Check now*, *Install now*, and switches for checking and for installing automatically. Admins see an "update available" badge in the header. |
| **Command line** | `--check-update` shows whether a newer version exists; `--update-now` installs it (start Prahari again afterwards). |

How each kind of install updates:

| You run | On update |
|---|---|
| `Prahari.exe` (Windows) | the exe replaces itself (the old one is kept as `Prahari.exe.old` until the new one has run for 3 minutes) and restarts in a new window |
| `run.bat` / Setup install (Python source) | the app files are replaced, with a backup in `%USERPROFILE%\.netsentinel\update\backup`, and it restarts in a new window |
| `Prahari.pyz` / Mac `.app` | it only tells you that a new version is available |

The folder holding `Prahari.exe` must be writable by the account that runs it (not `C:\Program Files`).

### Publishing a release (maintainer)

1. Bump `__version__` in `netscan/__init__.py`, commit and push.
2. `git tag v1.18.1 && git push origin v1.18.1` — GitHub Actions builds the exe and the app zip and creates a **draft** release. Installed copies never see drafts.
3. On the Mac that holds the signing key: `python3 tools/sign_release.py v1.18.1` — checks the files, signs `latest.json`, uploads it and publishes the release.

The signing key is `~/.config/netsentinel-release/update-signing-key.pem`. It is never committed. Keep a backup of it: without it no future update can be signed, and every install would need a manual reinstall.

## What was new in 1.17 — build artefacts from the command line

| Artefact | Command | Runs on |
|---|---|---|
| `Prahari.exe` (single file, Python bundled) | `pip install pyinstaller` then `pyinstaller netsentinel.spec` | Windows, no Python needed |
| `Prahari-Setup.exe` (installer) | `Build-Setup-EXE.bat` | Windows, downloads Python if missing |
| `Prahari.pyz` (one file, 126 KB) | `python3 make_pyz.py` | any OS with Python 3.9+ |
| `Prahari.app` (double-click) | `python3 make_mac_app.py` | macOS |
| `Prahari.exe` in the cloud | GitHub Actions workflow | Windows runner, no PC of yours |

The zip ships `netsentinel.spec` (so the exe build is one command, no long flag list),
`make_pyz.py` and `make_mac_app.py`, plus the ready-made `dist/Prahari.pyz` and
`dist/Prahari.app.zip`.

## What was new in 1.16 — runs on a Mac, and an exe without Windows

| Change | Why |
|---|---|
| **macOS support** | `./install-mac.sh` then `./run-mac.command` (double-clickable). Gateway, interfaces, mask, MAC and DNS now read with `route`/`ifconfig`/`scutil`, and ping uses the macOS flags. |
| **Cloud build for the exe** | `.github/workflows/build-windows-exe.yml` builds `Prahari.exe` on a real Windows runner in GitHub Actions and hands you the artifact — no Windows PC, no toolchain, free for a public repo. |

## What was new in 1.15 — nothing gets lost when the line drops

| Change | Why |
|---|---|
| **Alert outbox (store and forward)** | If a console cannot reach its mail server, the alert is written to disk and delivered the moment the link returns, subject marked `(delayed)` with the time it was really raised. No more silent gaps. |
| **Heartbeat in the UI** | Settings → *Heartbeat (dead-man's switch)*: URL, interval, last ping, failures, and a **Send test ping** button. Also shows how many alerts are queued. |
| **Auto-provisioned checks** | `--heartbeat-provision <healthchecks API key>` creates one check per site through their API and writes each ping URL into that site's `setup-<site>.cmd`. |
| **Per-site heartbeat in the fleet** | The generated setup files and checklists now carry `--heartbeat-url`, so the hotel PC starts pinging as soon as it is installed. |

## What was new in 1.14 — built for 50-100 hotels

| Change | Why |
|---|---|
| **Storage rewritten for concurrency** | One SQLite connection per thread, WAL mode, schema created once. A branch report now costs ~1 ms instead of 33 ms; 100 reports take ~110 ms total. |
| **Overview cache (4 s)** | The Locations view re-parses every branch payload; it is now cached, so 100 sites cost ~3 ms per request instead of ~30 ms, however many browsers are open. |
| **Locations search + grouping** | A search box over name, public IP and "no contact"; rows grouped by region (the part of the name after ` - `), capped at 60 with "showing 60 of N". |
| **Fleet from CSV** | `--fleet-csv sites.csv` (`name,region,email`) issues 100 tokens and 100 setup files in one command, with the region appended to the site name. |
| **Mass-outage digest** | If more than three sites go quiet in the same pass, you get **one** mail listing them ("12 sites lost contact — the cause is usually at head office") instead of twelve. |

## What was new in 1.13 — mail to the right manager

| Feature | What it does |
|---|---|
| **Per-site recipients** | Each property can carry its own IT manager list. "Lost contact with Udaipur" goes to Udaipur's IT and GM; "Lost contact with Goa" goes to Goa's. Set it in Settings → *Head office (hub)* next to each branch, or with `--fleet-emails`. |
| **Explicit recipient override** | `alerts.send_email(..., to=[...])` lets any alert target a list; sites with no list fall back to the main email list. |

## What was new in 1.12 — corporate office and hotels in one table

| Feature | What it does |
|---|---|
| **CORP and HOTEL labels** | The Locations view now includes the corporate office itself as the first row (badge **CORP**) followed by every property (badge **HOTEL**), with a "corporate office + N hotels" total. |

## What was new in 1.11 — the installer does Tailscale too

| Feature | What it does |
|---|---|
| **Silent Tailscale install** | `--install-tailscale` downloads the official MSI from pkgs.tailscale.com and installs it with `msiexec /quiet` — no clicking, no browser. |
| **Unattended tailnet join** | `--tailscale-key tskey-…` joins the private network with an auth key, so the hotel PC never has to open a login page. `--tailscale-name udaipur-reception` names it on the tailnet. |
| **Embedded in the site setup** | `--fleet-tailscale-key` puts that step inside each hotel's `setup-<site>.cmd`: Python, then Tailscale, then joining the hub — one double-click. |

## What was new in 1.10 — the zero-rupee chain

| Feature | What it does |
|---|---|
| **Tailscale-aware** | If Tailscale is installed, the console prints the address to open from anywhere and `--branch auto` uses it as the hub address. Free tier, works behind CGNAT, no public IP, no domain, no port-forward. |
| **Zero-cost recipe** | Section 6c below: six hotels, one console, ₹0/month — no VPS, no domain, no per-device licence. |

## What was new in 1.9 — running a chain of hotels

| Feature | What it does |
|---|---|
| **Fleet roll-out** | `--fleet-setup DIR --fleet-sites "Udaipur,Jaipur,…" --branch https://hub…` issues one token per site and writes a one-click `setup-<site>.cmd` plus a printed checklist for each hotel. Copy the folder to the hotel, double-click, done. |
| **Dead-man's switch** | `--heartbeat-url https://hc-ping.com/<uuid>` pings an outside service every 5 minutes with the site name. If the hotel's power or internet dies, *that* service tells you — a console inside the building cannot. |

## What was new in 1.8 — safe to publish

| Feature | What it does |
|---|---|
| **IP allow / deny lists** | `--allow-cidr 10.0.0.0/8,203.0.113.0/24` (or Settings → *Access & certificates*). Checked on **every** request before sign-in, so a console behind a tunnel is limited to known networks. Blocked attempts are logged as events. |
| **Trusted reverse proxy support** | `X-Forwarded-For` / `X-Real-IP` / `X-Forwarded-Proto` are honoured **only** from proxies you list (`--trusted-proxy`), so audit entries and lockouts show the real client address and never a spoofed one. |
| **TOTP two-factor for local accounts** | Enrol from the Users view (or API): secret, otpauth URI and ten single-use backup codes. Sign-in becomes password → 6-digit code. RFC 6238, verified against the published test vectors. |
| **Certificate lifecycle** | `--cert-status` shows expiry and the detected renewal tool; a watcher warns at `renew_days` (default 21) in the console, the event log and by email, runs your renewal command (win-acme/certbot/your script) and restarts to load the new certificate. `--csr DOMAIN` generates a key + CSR for your own CA. |
| **EULA** | `EULA.txt` — a short-form licence to start from before distributing. |

## What was new in 1.7 — the last two gaps that mattered

| Feature | What it does |
|---|---|
| **Host agent** | `run.bat --agent --console https://… --token nsk_…` on a server or critical PC reports CPU, memory, per-volume disk, uptime, top processes and service state every 60 s. The device drawer shows the metrics with bars, the Overview shows a host-health card, and CPU/memory/disk/service thresholds raise events. No service installed, nothing listens on the host. |
| **SIEM forwarding (CEF / RFC 5424)** | Every incident is forwarded to your SIEM over UDP or TCP as an ArcSight CEF line (severity, device, root cause, category, confidence) or plain RFC 5424 syslog. Splunk, QRadar, Sentinel, Wazuh and Graylog all parse it as-is. |
| **Native Slack and Teams cards** | Incidents arrive as a formatted Slack message (severity colour, device, root cause, confidence, numbered actions) or a Teams MessageCard — not a wall of JSON in a webhook. |

## What was new in 1.6 — enterprise groundwork

| Feature | What it does |
|---|---|
| **HTTPS** | `--tls` serves the console over TLS 1.2+, with HSTS, CSP and a `Secure` session cookie. Use `--tls-cert`/`--tls-key` with a certificate from your own PKI (the only thing a security review accepts); `--make-cert` creates a self-signed one for a lab. |
| **SSO (OpenID Connect)** | Entra ID / Okta / Keycloak / Google / Auth0 / ADFS-OIDC. Authorisation-code flow with PKCE, state and nonce, RS256 signature verified against the provider JWKS. Group claim mapped to Viewer/Engineer/Administrator, plus an email-domain allow-list. Fails closed. |
| **REST API + tokens** | `/api/v1/...` with `Authorization: Bearer <token>`, read/write scopes, hashed storage, last-used tracking, revocation, and an audit entry per call. |
| **SBOM + signing** | `python sbom.py` writes `sbom.json` (CycloneDX-style) for a security review; `sign_build.bat` signs the built exe with your code-signing certificate and timestamps it. |

## What was new in 1.5

| Feature | What it does |
|---|---|
| **Multiple locations** | One head-office console shows every branch: health, devices, open incidents, public IP, internet rate and last contact. Branches push to the hub every 30 s with a per-site token; a branch that goes quiet for 5 minutes raises "Lost contact" and another alert when it returns. |
| **One-file installer** | `Build-Setup-EXE.bat` produces `dist\Prahari-Setup.exe` using only Windows' own tools. That single exe unpacks the app, **downloads and installs Python silently if it is missing**, installs the extras, makes shortcuts and starts the console. |
| **Uninstaller + icon** | `uninstall.cmd` (with `/purge` for config and history), desktop/Start-menu shortcuts and a proper application icon. |

## What was new in 1.4

| Feature | What it does |
|---|---|
| **Roles** | Admin / Engineer / Viewer, enforced on the server for every action, with an audit trail of who did what. |
| **Reports view** | Availability per device for the last 1 / 7 / 30 days, mean time to resolve, incidents by severity, worst offenders, internet line changes — exportable as CSV. |
| **Dual-WAN detection** | Public IP is checked against five services at once, so two load-balanced internet lines are both visible; a change of public IP or ISP raises an alert (line failed / backup took over). |
| **VLAN-aware port mapping** | The SNMP poller now reads Q-BRIDGE-MIB as well as BRIDGE-MIB, so MAC-to-switch-port attribution works on VLAN-tagged networks, and it uses GETBULK (a 48-port switch is read in a handful of packets). |
| **WAN port recognition** | Router/switch interfaces named `wan`, `pppoe`, `gpon`, `ether1`, `sfp*`, or by ISP name are identified as the internet port and drive the WAN throughput figure. |

## What was new in 1.3

| Feature | What it does |
|---|---|
| **Continuous monitoring** | Polls every monitored device (default 60 s): latency, packet loss, up/degraded/down. No more one-off snapshots. |
| **Incidents** | Opens an incident after N bad polls, escalates when it gets worse, closes itself on recovery, with a full timeline. |
| **Diagnosis** | Rule-based root cause, confidence, evidence, ordered actions, user impact and the data that would raise confidence — no AI, no API key, nothing leaves the PC. |
| **NetFlow v5/v9, IPFIX, sFlow** | Real per-device internet usage, ranked by rate and by data used today. |
| **Syslog receiver** | Firewall/switch logs become events, and matching lines are quoted inside the diagnosis. |
| **Email + webhook alerts** | SMTP (SSL/STARTTLS) and a generic JSON webhook, gated by severity, with a test button. |
| **Sign-in and roles** | PBKDF2 passwords, session cookies, lockout after 5 failures, CSRF guard. On automatically when the dashboard is shared on the LAN. |
| **NOC dashboard** | Six views — Overview, Devices, Incidents, Traffic, Events, Settings — in the dense, dark style of Cisco/Palo Alto consoles, plus a device/incident drawer. |
| **Settings in the UI** | Thresholds, poll interval, monitoring scope, flow/syslog ports, email, webhook, users — saved to `config.json`. |

---

## 1. Install and run on Windows

| Step | Action |
|------|--------|
| 1 | Double-click **`install.bat`** — creates a private Python environment (needs Python 3.9+ from [python.org](https://www.python.org/downloads/windows/), tick *Add python.exe to PATH*). |
| 2 | Double-click **`run.bat`** — scans the network, starts monitoring, opens the console. |
| 3 | Allow the Windows Firewall prompt if it appears. |

Later runs need only `run.bat`. Single-file build: **`build_exe.bat`** → `dist\Prahari.exe`.
Start at login: **`autostart_install.bat`** (as Administrator) / remove with `autostart_remove.bat`.
Share the console with another laptop: **`dashboard_lan.bat`** (+ `allow_firewall.bat` once).
Reopen the console: **`open_dashboard.bat`**.

---

## 1aa. Building each artefact, command by command

Everything below is a single command; nothing needs a flag list typed by hand.

**Windows exe (on a Windows PC, or a Windows VM/runner):**

```
pip install pyinstaller
pyinstaller netsentinel.spec
:: result: dist\Prahari.exe
```

**Windows installer that also fetches Python:**

```
Build-Setup-EXE.bat          :: result: dist\Prahari-Setup-<version>.exe
```

**One file that runs anywhere Python exists (built here, tested):**

```
python3 make_pyz.py          :: result: dist/Prahari.pyz  (126 KB)
python3 dist/Prahari.pyz --help
```

**macOS application bundle (double-click):**

```
python3 make_mac_app.py      :: result: dist/Prahari.app
open dist/Prahari.app
```

**No Windows machine at all:** push the folder to GitHub and run the included workflow —
*Actions → Build Windows EXE → Run workflow* — then download the exe from the run page.

What is **not** possible, and why: a Linux or macOS machine cannot cross-compile a Windows
`.exe`. PyInstaller builds for the OS it runs on, and there is no MinGW/Wine toolchain in
this environment. So the exe is always produced *on* Windows — your PC, a hotel PC, a VM, or
GitHub's Windows runner.

## 1a. On a Mac

```
cd Prahari
./install-mac.sh        (once)
./run-mac.command       (or double-click it in Finder)
```

The dashboard opens at `http://127.0.0.1:8777`. A Mac is a perfectly good **head-office
hub** — it polls its own LAN, collects the hotels, sends the emails and pings the heartbeat.
It cannot launch RDP into a Windows machine (no `mstsc`), so use the web-admin, SSH, VNC and
Wake-on-LAN buttons from the Mac instead.

## 1b. One .exe that installs everything by itself

You asked for a single file that pulls in whatever it needs. Build it once, on any
Windows PC, with **no downloads required to build** (it uses `iexpress.exe` and
PowerShell, which ship with Windows):

```
Build-Setup-EXE.bat      ->  dist\Prahari-Setup-1.5.0.exe
```

That `.exe` is the whole product. When someone runs it, `bootstrap.cmd` inside it:

1. unpacks the app to `%LOCALAPPDATA%\Prahari` (or `%ProgramData%` with `/allusers`)
2. finds Python 3.9+; **if there is none, it downloads the official installer from
   python.org and runs it silently** (`/quiet PrependPath=1 Include_pip=1`)
3. creates the private environment and installs the two optional extras
4. makes a desktop shortcut, a Start-menu entry and an uninstaller
5. opens the firewall for the dashboard and flow/syslog — **only if run as Administrator**
6. starts Prahari

Options: `/autostart` (also start at every login, needs Administrator), `/no-run`,
`/allusers`. A log is written to `%TEMP%\netsentinel-setup.log`.

Two other routes, if you prefer:

| Route | Produces | Needs |
|---|---|---|
| `Build-Setup-EXE.bat` | `Prahari-Setup.exe` (installer, downloads Python if missing) | nothing extra |
| `build_exe.bat` | `dist\Prahari.exe` (the app only, Python bundled inside, no install) | Python on the *build* PC (PyInstaller is installed automatically) |
| `makensis installer.nsi` | classic Add/Remove Programs installer | NSIS, if you already use it |

**Honest note:** these build scripts are written to run on Windows, and I could not
compile or execute a Windows binary in my environment — there is no Windows toolchain
here. The Python side is tested; the two `.bat`/`.cmd` builders are written defensively
(they check every step and log), but the first build is the real test. If anything trips,
send me the console output and I will fix it.

## 2. The nine views

![Locations](screenshot-locations.png)

| View | What you get |
|---|---|
| **Overview** | Health score gauge, KPI strip (monitored devices, open incidents, internet throughput, public IP, next poll), active incidents, top bandwidth users, internet path with per-target latency/loss. |
| **Devices** | Dense table: status dot, type badge, IP, name, MAC/vendor, latency sparkline, loss, down/up rate, open ports, remote button. Filter by group, "monitored only", free-text search. Click a row for the full evidence trail. |
| **Incidents** | Every incident with severity, device, open time, state and confidence. Click for the diagnosis drawer. |
| **Traffic** | Who is using the internet: rank, rate down/up, data used today, share bar — and a setup hint naming the exact command per router brand until flow data arrives. |
| **Reports** | Availability per device (1/7/30 days), MTTR, incidents by severity, worst offenders, internet line changes, CSV export. |
| **Locations** | Head-office view: every branch's health, devices, incidents, public IP, internet rate and last contact. Only shown when this PC is a hub or a branch. |
| **Users** | Administrator only: every account with its role, created date and last sign-in; add a user, set anyone's password, remove an account. The admin row is marked "you" and cannot be removed. |
| **Events** | Syslog lines, audit trail and Prahari's own events, severity-coded. |
| **Settings** | Everything configurable, with **Send test alert**. |

![Devices](screenshot-devices.png)
![Reports](screenshot-reports.png)
![Incident diagnosis](screenshot-incident.png)

---

## 3. Monitoring, incidents and diagnosis

Every `poll_interval_seconds` (default 60) each monitored device is probed three times:
ICMP first, then a TCP connect to a port it is known to listen on (because Windows
firewalls often block ping). Latency is the average, loss is the percentage lost.

```
state = down      no answer at all
        degraded  loss >= loss_warn_pct (3%)  or latency >= latency_warn_ms (150 ms)
        up        everything under the thresholds
```

The incident state machine:

```
bad polls  >= open_after_bad_polls   (2)  -> incident opens, diagnosed, alerted
severity increases                        -> incident escalates, alerted again
good polls >= resolve_after_good_polls (3) -> incident resolves automatically
```

**Monitored by default:** router/firewall, switches, access points, DVR/NVR, cameras,
NAS, servers, printers and KOT printers. Phones, IoT and unknown devices are listed but
not polled (tick them in Settings if you want them).

**What the diagnosis does.** It reasons over the whole picture, not just the one device:
whole site down (power), gateway down (firewall), internet targets down while the gateway
answers (ISP/WAN), most of the LAN unreachable but the gateway up (switching/loop), a
single access point down while its peers are fine (PoE/cable), a single device down
(that device), many devices slow at once (congestion, with the top talker named), and it
quotes matching firewall syslog lines and lists the missing data (no flow export, no
syslog, no SNMP) that would raise its confidence. Every diagnosis states its confidence
as a number, so a weak guess looks weak.

There is deliberately **no AI** in the diagnosis path: it is deterministic, auditable, and
sends nothing off the machine. (A key-based AI layer is easy to add later if you want it.)

---

## 3b. Predictions, and why they beat thresholds

A fixed threshold ("latency over 150 ms is bad") is wrong in both directions: it misses a
device that has doubled but stayed under the limit, and it cries wolf on a slow-but-normal
microwave link at peak hour. Prahari keeps, for each device, a separate mean and spread for
**each hour of the day** from 14 days of samples, then scores each new reading against the
profile for *that hour*. A reading is reported only when it is at least 3σ out **and**
materially bad (≥25 ms, ≥5% loss) — which is why the alert reads "12σ above the usual 5 ms"
rather than "high latency".

Forecasting is a least-squares line through the last 14 days of disk/memory samples from the
host agents. It only forecasts *upward* trends above 50%, and it says nothing at all when the
slope is flat — silence is the correct answer most of the time.

Both live in the Overview as the **Predictions** card, in `GET /api/v1/insights`, and as
events in the log. No ML library, no training, no data leaving the machine.

## 3b2. SNMPv3, and why it was worth the trouble

v2c puts the community string in every packet in clear text, which any security baseline
prohibits and any guest on the Wi-Fi can capture. v3 signs and encrypts:

```
Settings -> SNMPv3:  user, auth password, auth protocol, privacy password
```

With auth+priv set, every `get`/`walk` in the console goes through USM instead of v2c —
nothing else changes, and the posture card stops reporting `snmp-v2c`. Key localisation is
the RFC 3414 algorithm (one hash over the password repeated to 1 MB, then the engine-id
mix), checked against the published vectors for `maplesyrup`:

```
MD5  -> 526f5eed9fcce26f8964c2930787d82b
SHA1 -> 6695febc9288e36282235fc7151f128497b38f3f
```

DES privacy is deliberately unsupported (deprecated by every vendor); AES-128 is what
current switches and APs offer.

## 3b3. Wi-Fi health — the number that matches the complaint

Guests do not complain about "packet loss", they complain that the Wi-Fi is slow. The honest
signal is the retry rate from the standard IEEE802dot11 counters:

| Retry rate | Meaning |
|---|---|
| under 10% | healthy |
| 10-25% | fair - interference or too many clients per radio |
| over 25% | poor - this is the AP people are complaining about |

Rates come from two readings of the cumulative counters, so the first pass only establishes
a baseline. Radios are read every five minutes by the poller and shown on the Overview and in
`GET /api/v1/insights`.

## 3b4. Open ports, and how to close them

The **Exposure** tab lists every open port the scan found, graded, with the fix. The
catalogue covers about 35 services (FTP, Telnet, TFTP, SNMP, SMB, RDP, VNC, rpcbind, NFS,
SMB, SQL/MySQL/Postgres/Mongo/Redis/Elastic, JetDirect, TR-069, Winbox, and more). Each
entry has three parts:

- **Why it matters** — one sentence a manager understands
- **How to close it** — the actual command or menu, per platform
- **Keep it open only if** — the legitimate case, so nobody breaks the hotel Wi-Fi chasing a score

Examples of what it says:

| Port | What it tells you to do |
|---|---|
| 23 Telnet | `no ip telnet server` (Cisco), `/ip service disable telnet` (MikroTik), untick Telnet in the web UI (Aruba/TP-Link/D-Link) |
| 80 on a DVR | enable HTTPS and turn the HTTP listener off; if the device has no HTTPS, keep its admin page on a management VLAN |
| 3389 RDP | never port-forward; restrict to an admin subnet, enable NLA (`enable_rdp.bat` does it), require MFA, prefer VPN/Tailscale |
| 161 SNMP | move to SNMPv3 auth+priv (Settings → SNMPv3); if you must keep v2c, long random community + allow only the monitor |
| 445 SMB | disable File and Printer Sharing on PCs that do not share, restrict to file servers, never port-forward |
| 9100 print | restrict to the POS/KOT subnet at the switch ACL, or use IPP with authentication |

**Download the hardening plan** produces a Markdown file grouped by device, top risk first,
that a technician can work through line by line and tick off.

## 3b5. Factory passwords: how the check works, and its limits

The **Exposure** tab has a *Check factory passwords* button; the same thing is in Settings.
It is opt-in, and refuses to run until you tick "I own this network and may test its
devices" and list the IPs it may touch.

| Protocol | How success is decided | What it finds |
|---|---|---|
| HTTP admin page | Basic or Digest auth answered with 200/302 instead of 401 | cameras, printers, APs, switches with an HTTP login |
| RTSP (554) | `DESCRIBE` returns `200 OK` instead of `401` | camera streams open to a factory login |
| FTP (21) | `USER anonymous` / `PASS` returns `230` | anonymous file access on a NAS or DVR |
| SNMP (161) | a GET answers on the community `public` | not a guess - the default is the default |

The credential list is 20 published factory pairs, tried **once each**, with a pause between
attempts and a hard cap per device (12 by default). There are no wordlists, no repeats, no
lockout games: this is a defaults check, not a brute-force tool.

**Form logins are not guessed.** Most recorders (Hikvision, Dahua, CP Plus) use an HTML form
or a vendor API where a wrong password and a right one look the same from outside, and
hammering the form locks the account. Those devices get a `medium` finding that says
"factory login page - verify by hand", so nothing is broken and nothing is claimed that was
not proven.

The password is shown in the finding (you need it to know which device to fix) but is
**never written to the event log or the audit trail** - the log records only which device and
which rule fired.

## 3c. Security posture — the findings that matter in a hotel

`POST /api/v1/insights` and the Overview card grade the network 0-100 and list findings with
a fix for each:

| Rule | Why it matters |
|---|---|
| `cctv-admin-exposed` | A recorder whose web page answers on port 80 with the factory password is how hotel cameras end up on the internet. |
| `telnet-open` | Passwords in clear text on switches and APs. |
| `admin-http-only` | Device admin over plain HTTP — anyone on the guest Wi-Fi can sniff the session. |
| `snmp-default-community` | `public` means anyone can read the device's whole configuration and port counters. |
| `rdp-open`, `smb-open`, `ftp-open` | Lateral movement paths. |
| `console-no-tls`, `console-no-allowlist`, `console-no-2fa`, `console-no-heartbeat` | The console grading itself, so you see your own gaps next to the network's. |

Nothing is exploited: every finding comes from ports, banners and SNMP answers the scan
already collected.

## 4. "Who is using the internet" — the honest part

A PC cannot see other devices' traffic by itself. Prahari supports three collectors
and always labels which one the numbers came from.

| Collector | What you get | Needs |
|---|---|---|
| **NetFlow v5/v9, IPFIX, sFlow** (best) | True per-device internet usage: rate now and data used today | Flow export enabled on the router/firewall, pointed at this PC (UDP 2055 / 6343) |
| **SNMP counters** | Per-port traffic on the switch/router, mapped to devices through the MAC table (BRIDGE-MIB **and Q-BRIDGE-MIB**, so VLAN'd switches work too) | SNMP enabled with community `public` |
| **Passive capture** | Bytes per LAN IP that pass this PC's NIC | `scapy` + Npcap + Administrator |

### Turn on flow export

- **MikroTik** — `/ip traffic-flow set enabled=yes interfaces=all` and
  `/ip traffic-flow target add address=<this PC>:2055 version=9`
- **Cisco IOS** — `ip flow-export destination <this PC> 2055` and `ip flow-export version 9`,
  then `ip flow ingress` on the LAN interface
- **Fortinet** — `config system netflow` → `set collector-ip <this PC>`, `set source-ip <lan ip>`
- **pfSense / OPNsense** — install *Soft Flowd*, set the destination to this PC:2055
- **UniFi** — Settings → Traffic & Security → *Flow* → enable, collector = this PC
- **Juniper / Aruba / HPE** — `set services flow-monitoring version9 template …` /
  `ip flow-export destination`
- **sFlow** (switches that only speak sFlow) — target this PC on UDP 6343

The Traffic view keeps a setup hint visible until the first flow packet arrives, and shows
the exporter addresses it is receiving from. If nothing arrives, the view says so instead
of inventing numbers.

---

## 5. Syslog and alerts

The syslog receiver listens on **UDP 5514** (so it can coexist with an existing syslog
server on 514). Point the firewall at this PC:

```
Cisco:     logging host <this PC> transport udp port 5514
MikroTik:  /system logging action add name=ns target=remote remote=<this PC> remote-port=5514
Fortinet:  config log syslogd setting → set server <this PC> / set port 5514
```

Lines matching the alert patterns in `config.json` (`link … down`, `ipsec … down`,
`failover`, `cpu/memory high`, `temperature high`) are stored as events and quoted inside
the matching incident's diagnosis.

**Alerts** are email (SMTP, SSL or STARTTLS) and/or a JSON webhook (Slack, Teams,
anything). Configure in **Settings → Email alerts / Webhook**, press **Send test alert**,
and set the minimum severity per channel. Alerts fire on incident open, escalation and
resolve.

---

## 6. Multiple locations (head office view)

Reporting is **outbound only** — the hub never reaches into a branch, so it works across
a VPN, a port-forward, or a public hub behind HTTPS.

**On the head office PC:**

```
run.bat --site-name "Head Office" --hub
run.bat --new-branch-token "Branch - Whitefield"      (prints the token once)
```

or in the dashboard: Settings → *Head office (hub)* → tick the box, add a branch, copy the
token it shows. The token is stored **only as a SHA-256 hash**; removing a branch kills its
token immediately.

**On each branch PC:**

```
run.bat --site-name "Branch - Whitefield" ^
        --branch http://<head-office-ip>:8777 ^
        --token ns_xxxxxxxxxxxxxxxx
```

The branch then POSTs a compact summary every 30 s (health, devices, open incidents with
their category, public IP/ISP, internet rate, gateway state). The **Locations** view shows
one row per site — health, devices, incidents, worst incident, public IP, internet rate,
last contact — plus totals across the company. Click a site for its open incidents.

A site is marked **no contact** after `hub.expect_minutes` (default 5) without a report,
which raises an event, an email and a webhook; it raises another when the site returns.
That covers the case ITWatcher calls "Lost contact with <branch>".

## 6b. Running several sites (a hotel chain)

The shape for 5–6 properties: **one hub** (a small VPS or a PC at head office, always on)
and **one branch at each hotel**. Branches only ever dial *out* to the hub, so no hotel
needs a public IP, a port-forward or a static address.

```
head office / VPS
  run.bat --site-name "Head Office" --hub --lan --tls

once, on the hub, to prepare the chain
  run.bat --fleet-setup C:\fleet --fleet-sites "Udaipur - Lake Road,Jaipur - MI Road,Mount Abu,Jodhpur,Rishikesh,Goa - Candolim" --branch https://hub.yourgroup.in

at each hotel
  copy the Prahari folder + its setup-<site>.cmd there, run it
```

`--fleet-setup` writes `setup-<site>.cmd` (installs if needed, then joins that site),
`CHECKLIST-<site>.txt` (what the local person must switch on: SNMP, NetFlow, syslog, UPS,
autostart) and `FLEET-SUMMARY.json` with the tokens. Tokens are stored on the hub as
SHA-256 hashes only, one per site, so revoking a hotel is one click.

Then the **Locations** view is your chain: one row per property with health, devices, open
incidents, public IP and internet rate, plus a company-wide total. A hotel that stops
reporting for 5 minutes raises *"Lost contact with Udaipur"* by email/webhook/Slack/Teams.

**Two layers, so a dead line cannot hide an incident.**

1. **The branch queues its own alerts.** When a hotel loses its internet, its console still
   detects the fault and writes the email to a local outbox. The moment the link is back it
   sends them, marked `(delayed)`, with the original time. So the hotel's manager learns what
   happened during the outage, even though nothing could leave the building at the time.
2. **The hub notices the silence.** "Lost contact with <site>" comes from the head office,
   because the hub is outside the hotel.

**The one thing that must not be inside the hotel** is the alarm for the hotel being
offline. Set a heartbeat on the hub (and optionally each branch):

```
run.bat --heartbeat-url https://hc-ping.com/<your-uuid>          (one check for the hub)
run.bat --heartbeat-provision <healthchecks API key>            (one check per site, automated)
```

`--heartbeat-provision` calls the healthchecks.io API, creates a check named after each
site, and stores the ping URL on that site — the next `--fleet-setup` puts it into
`setup-<site>.cmd`, so the hotel PC starts pinging itself on install. One check on the hub
covers all 100 hotels (the hub already knows who is reporting); per-site checks are for the
properties you want watched independently. The free plan allows 20 checks.

healthchecks.io, UptimeRobot or your own endpoint then emails you when the pings stop —
which is exactly what happens when the power or the ISP at that property goes down.

## 5b. How the email actually gets sent

Prahari sends mail the way an old-fashioned script does: it **talks to an SMTP server
you already have** — no third-party service, no account with me, nothing to sign up for.
You give it a mailbox and it uses it as the sender.

**Settings → Email** (or `config.json`):

| Field | What to put | Notes |
|---|---|---|
| Enabled | tick | nothing is sent until you tick it |
| SMTP host | `smtp.zoho.in`, `smtp.gmail.com`, `smtp.office365.com` | the host your mailbox provider documents |
| Port | `465` (SSL) or `587` (STARTTLS) | 465 is the usual choice for Zoho/Gmail |
| SSL / STARTTLS | match the port | both are supported |
| User name | the full mailbox, e.g. `alerts@hotelgroup.in` | |
| Password | an **app password**, not your login password | Gmail and Zoho both require an app-specific password when 2FA is on |
| From | same as the user name | some servers reject a mismatch |
| To | the main list, comma separated | `it-head@hotelgroup.in, ops@hotelgroup.in` |
| Minimum severity | `medium` is a good default | `low` will mail you about everything |

Press **Send test alert** and it reports each channel separately (`email: sent`,
`siem: sent`, …) or the exact error — `535 authentication failed` means the password, not
the code.

**When mail is sent**

| Trigger | Subject |
|---|---|
| Incident opens | `[Prahari] <Device> is down` — with root cause, confidence, the numbered actions and the evidence |
| Incident escalates (severity rises) | `[Prahari] ESCALATED: <Device> …` |
| Incident resolves | `[Prahari] Resolved: <Device> …` |
| A branch stops reporting for N minutes | `[Prahari] Lost contact with <site>` → that site's managers |
| The branch comes back | `[Prahari] <site> is back` |
| TLS certificate inside the warning window | `[Prahari] TLS certificate expires in N days` |
| Host agent over threshold (CPU/disk/service) | an event, and the incident path if it crosses the poller thresholds |

Mail is rate-limited by design: one message per state change, not one per poll, so a
flapping link sends "down" once, "escalated" if it worsens, "resolved" when it settles.

**Who gets it — two levels**

- **The hotel's own console** mails its own list. Udaipur's manager hears about Udaipur's
  KOT printer directly, without waiting for head office.
- **The head-office console** mails the group list, and for *lost contact* it uses the
  per-site list if one is set (Settings → hub → the email box beside each branch).

```
--fleet-emails "Udaipur - Lake Road=it.udaipur@hotelgroup.in,gm.udaipur@hotelgroup.in;Goa - Candolim=it.goa@hotelgroup.in"
```

Verified here against a local SMTP server: the main list received the corporate incident,
Udaipur's two managers received Udaipur's lost-contact mail, Goa's manager received Goa's,
and a site with no list fell back to the main list.

**If the hotel's own internet is down**, its console cannot send anything — that is what the
heartbeat (healthchecks.io) is for, and why the hub's lost-contact mail matters.

## 6g0. Backups you can actually restore

```
run.bat --backups                          list them
run.bat --restore netsentinel-20261201.db --confirm
```

The restore verifies the file, keeps the current database as
`netsentinel.db.pre-restore-<stamp>`, and rolls back if the new file fails `integrity_check`.
Restart the console afterwards.

## 6g. The monthly report

```
run.bat --sla-report "Udaipur - Lake Road" --sla-month 2026-11 --sla-out reports
```

or in the console: **Reports → Last month (PDF)**. The file is named
`Prahari-SLA-<site>-<YYYY-MM>.pdf` and contains:

| Page | Contents |
|---|---|
| 1 | Site, month, availability %, devices, incidents opened/resolved, MTTR, longest outage, per-device table (uptime, average and 95th-percentile latency, loss, incidents), incident list with durations, host disk bars, Wi-Fi retry bars |
| 2 | How every number was measured — so the owner can argue with the method instead of guessing at it |

Availability is the share of polls that answered; a device switched off for a week counts as
unavailable, which is the honest reading for an SLA.

## 6h. The topology map

LLDP and CDP are the only reliable way to learn which switch port feeds which access point.
The console walks both tables, matches the reported chassis id (a MAC) to a device it already
discovered, and builds a depth-first layout from the gateway. Neighbours with no IP of their
own are shown grey, so a map is never missing a link just because the far end was not scanned.

If the map is empty, the devices are not announcing: on Cisco `cdp run` (or `lldp run`), on
Aruba/UniFi/Omada enable LLDP in the profile, and make sure SNMP can read the device.

## 6f. Upgrading a hundred branches

Branches sit behind hotel broadband and only dial outwards, so the hub cannot push to them.
Instead the hub *answers* each branch report with the build it should be running:

1. Publish a signed release as usual (tag, then `tools/sign_release.py`, see 1.18 above).
2. On the hub: Settings → **Fleet update** — type the version, e.g. `1.22.1`, and save.
3. Each older branch, on its next report, installs the newest signed release from GitHub and
   restarts — even if automatic installs are off on that branch. A bad signature or checksum is
   refused; a version that will not start is rolled back automatically.
4. The Locations table shows each branch's version, so you can watch the fleet converge.

Branches with automatic installs on (the default) update within 6 hours anyway; the hub setting
is for rolling out *now*, or for fleets where automatic installs are switched off.
On a site that must never self-update, turn off *Install them automatically* (Settings → Updates)
and set `branch.auto_update: false`.

## 6e. Capacity: what 50-100 hotels actually costs

Measured on this build (synthetic load, 100 branch payloads):

| Operation | 100 sites | Notes |
|---|---|---|
| One branch report (write) | ~1 ms | 100 reports ≈ 110 ms |
| Locations view (cached) | ~3 ms | was ~30 ms before the cache |
| Locations view (cold) | ~11 ms | recomputed every 4 s |
| Event writes | ~1 ms each | WAL keeps readers out of the writer's way |
| Inbound load | 3.3 req/s at 30 s, 1.7 req/s at 60 s | trivial for any PC |

**Sizing the hub:** a 4-core mini PC with 4 GB RAM and an SSD is plenty for 100 sites;
the process sits well under 200 MB. What matters more than CPU is that the hub PC is
**never switched off** — a laptop that sleeps is a hub that misses alerts.

**Tuning for 100 hotels:**

- Set the branch report interval to 60 s in each site's setup (`branch.interval_seconds`),
  halving the request rate; a hotel's status does not change meaningfully in 30 s.
- Group names by region (`Hotel Goa Candolim - Goa`) so the Locations view groups itself.
- Keep the **hub's** email list for group heads, and per-site emails for local managers.
- The digest threshold (three sites at once) is what stops a mail storm when the hub's own
  link drops — it is the one failure mode that looks like 100 separate faults.

**What breaks first at this size:** nothing in the code path, but the *hub's own internet*.
If the hub loses its line, every branch looks "lost". That is why the digest says so in
words, and why the hub needs its own heartbeat.

## 6d. How the corporate office and the hotels fit together

```
   CORPORATE OFFICE (one PC)                          HOTEL (one PC each)
   ┌───────────────────────────┐                     ┌───────────────────────────┐
   │ Prahari  --hub        │   every 30 seconds  │ Prahari  --branch     │
   │ • scans its own LAN       │◀──── HTTPS POST ────│ • scans the hotel LAN     │
   │ • polls its own devices   │  /api/branch/report │ • polls printers, DVR, APs│
   │ • keeps every hotel row   │   X-Branch-Token    │ • raises its own incidents│
   │ • Locations = CORP + N    │                     │ • sends a summary only    │
   └───────────────────────────┘                     └───────────────────────────┘
              ▲                                                  │
              │ you open this from anywhere                      │ outbound only,
              │ (Tailscale, no port-forward)                     │ nothing listens
```

**What travels up:** one small JSON per hotel per 30 s — site name, health score, device
count, gateway state, public IP and ISP, internet rate, and the open incidents with their
severity and title. Not the raw history, not credentials, not traffic details.

**What stays local:** the full device table, every sample, the diagnosis detail, the
syslog and the audit trail. So a hotel keeps monitoring and alerting even when the
corporate office PC is off — the console in the hotel is a complete console, not a remote
agent.

**On the corporate console** the Locations view is the chain:

| Badge | Row | What you get |
|---|---|---|
| **CORP** | `Corporate Office - Bengaluru` | its own health, devices, incidents — this PC |
| **HOTEL** | `Udaipur - Lake Road` | health, devices, incidents, public IP/ISP, internet rate, last contact |
| **HOTEL** | `Goa - Candolim` | same, and `no contact` if it stops reporting |

Set the names you want to see: `--site-name "Corporate Office - Bengaluru"` on the hub,
`--site-name "Udaipur - Lake Road"` on that hotel. The hub's own name comes from its
`site_name`, and each hotel's name comes from the token it was issued (so the fleet
generator's `--fleet-sites` list is literally what appears in the table).

Clicking a hotel row opens its open incidents. The hotel's own console (over Tailscale) has
everything else.

## 6c. The zero-cost version (no VPS, no domain, no licence)

Everything below is free software on hardware you already own.

| Need | Free answer | Limit you accept |
|---|---|---|
| Reach each hotel from Bengaluru | **Tailscale** free tier (100 devices, 3 users) | You must install it on your laptop and each hotel PC |
| Hub that all sites report to | Any **already-on PC** — Bengaluru office, or the head-office PC at one hotel | If that PC sleeps, the chain view pauses |
| Certificate | `tailscale cert <name>.ts.net` (free, real Let's Encrypt) or `--make-cert` (self-signed) | Self-signed warns once per browser |
| Site-down alarm | **healthchecks.io** free (20 checks) or UptimeRobot free (50 monitors) | 5-minute granularity |
| Alert delivery | Email from the hotel's own SMTP / a free Gmail app password | Not instant like SMS |
| Hardware | The reception/billing PC already at each hotel | Monitoring only runs while that PC is on |

**The installer now does Tailscale for you.** Create one auth key in the Tailscale admin
console (*Settings → Keys → Generate auth key*, set it to **reusable** with a 90-day expiry,
or one **single-use** key per hotel for tighter control), then:

```
run.bat --install-tailscale --tailscale-key tskey-auth-xxxxxxxx
```

That downloads the MSI, installs it silently, joins the tailnet and prints the address to
use. In the fleet generator, add `--fleet-tailscale-key tskey-…` and every hotel's
`setup-<site>.cmd` will install Python, install Tailscale, join the network and start
reporting — the local person double-clicks one file and nothing else.

Keep the auth key off shared drives: anyone holding it can join your tailnet. Single-use
keys per hotel (or revoke the key in the admin console after the roll-out) close that gap.

**Setup, in order — nothing to buy:**

1. On your Bengaluru laptop and on one hotel PC (make it the hub): install Tailscale, sign in
   with the same account. Free tier covers six sites plus you.
2. On the hub PC: `run.bat --site-name "Head Office" --hub --lan --tls --allow-cidr 100.64.0.0/10,127.0.0.1`
   (that allow-list means *only* your Tailscale devices can reach the console).
3. On the hub: `run.bat --fleet-setup C:\fleet --fleet-sites "Udaipur,Jaipur,Mount Abu,Jodhpur,Rishikesh,Goa" --branch auto`
   — `auto` picks up the hub's Tailscale address, so the six setup files already point home.
4. Copy the folder to each hotel PC, run `setup-<site>.cmd`. No ports, no router changes.
5. Open `https://<hub-name>.ts.net:8777` from anywhere — or `https://<hotel>.ts.net:8777` for a
   single property without the hub.
6. Free dead-man's switch: create one check per site at healthchecks.io, copy its URL, run
   `run.bat --heartbeat-url https://hc-ping.com/<uuid>` on that PC.

What you give up by not spending: no cloud backup of history (it lives on each PC), no
vendor SLA, and the hub is only as reliable as the PC it runs on. For six hotels that is a
reasonable trade — the alternative is ₹400/month for a VPS, which only buys the hub being
always on.

## 7. Roles, reports and line changes

**Roles** (Settings → *Require sign-in*):

| Role | Can |
|---|---|
| **Viewer** | Read everything. No rescan, no remote sessions, no settings. |
| **Engineer** | Viewer + rescan, remote sessions, Wake-on-LAN, acknowledge incidents, label devices. |
| **Administrator** | Engineer + settings, alert tests, user management. |

Permissions are checked on the server for every POST, not hidden in the browser. The
**Users** view (Administrator only) lists every account with its role, creation date and
last sign-in, and lets an administrator add a user, set anyone's password or remove an
account — the account you are signed in with cannot be removed. Each
action lands in the event log as `audit <user>` — who launched which remote session, who
changed which setting — so there is a record of the day.

**Reports** answers "has this been flaky all week?" rather than "is it up now?":

- **Availability per device** over the last 1, 7 or 30 days from the sample history — a
  degraded sample counts as half available, so a device that answers slowly does not score
  a perfect 100%.
- **Mean time to resolve** across incidents, incident counts by severity, and the devices
  that generate the most incidents.
- **Internet line changes** — every public-IP change with its timestamp.
- **Export CSV** for the whole table.

**Dual-WAN / line failover.** The public IP is looked up from five services at once
(ipinfo, ipify, icanhazip, AWS checkip, Cloudflare trace). A firewall load-balancing two
lines answers with two different addresses, which is exactly how both lines become
visible; the Overview shows a **dual WAN** badge with both addresses. When the set of
addresses changes, the event log, email and webhook all report it — because a silent
failover to a backup line is usually the reason a site "suddenly" got slow.

## 8. Enterprise deployment: HTTPS, SSO, API, signing

**HTTPS.** For anything beyond a lab, terminate or serve TLS properly:

```
run.bat --tls --tls-cert C:\certs\netsentinel-chain.pem --tls-key C:\certs\netsentinel-key.pem
```

The certificate must contain the host name clients use (a SAN entry), issued by a CA they
trust. `--make-cert` writes a self-signed pair to `%USERPROFILE%\.netsentinel\` — good for
a pilot, but browsers will warn until that certificate is trusted, and a security review
will reject it. With TLS on, the console sends HSTS, a restrictive CSP, `X-Frame-Options:
DENY` and a `Secure; HttpOnly; SameSite=Strict` session cookie.

**Single sign-on (Entra ID, Okta, Keycloak, Google, Auth0, ADFS over OIDC).**

```
run.bat --lan ^
  --sso-issuer https://login.microsoftonline.com/<tenant-id>/v2.0 ^
  --sso-client-id <application-id> ^
  --sso-client-secret <secret> ^
  --sso-redirect https://netsentinel.yourco.com:8777/auth/callback ^
  --sso-domains yourco.com ^
  --sso-role-map net-admins=admin,net-techs=engineer,net-viewers=viewer
```

Register the redirect URI at the provider, grant the `openid profile email` scopes, and add
the group claim to the token (Entra: *Token configuration → groups claim*). Then:

- the sign-in page shows **Sign in with your company account**; local accounts remain as
  break-glass,
- the ID token signature is verified against the provider's JWKS with RS256, and `iss`,
  `aud`, `exp`, `iat` and `nonce` are all checked,
- the group claim decides the role; anything unmatched becomes `viewer`,
- only addresses in `--sso-domains` may sign in,
- every sign-in is written to the event log with the address and the role granted.

If the provider is unreachable, or `cryptography` is not installed, SSO stays **off** and
says why in the console — it never falls back to accepting unverified tokens.

**REST API for automation.**

```
run.bat --api-token-create siem-poller --api-token-scope read
```

| Endpoint | Returns |
|---|---|
| `GET /api/v1/state` | the whole live snapshot (settings excluded) |
| `GET /api/v1/devices` | device inventory with state, latency, loss, ports |
| `GET /api/v1/incidents?state=open` | incidents with diagnosis |
| `GET /api/v1/reports?hours=168` | availability and MTTR |
| `GET /api/v1/traffic` | per-device internet usage |
| `GET /api/v1/sites` | branch roll-up |
| `GET /api/v1/health` | health summary (good for an uptime probe) |
| `GET /api/v1/hosts` | host agent metrics with threshold flags |
| `POST /api/v1/agent/report` | where the agent posts (needs a `write` token) |
| `POST /api/v1/incidents/<id>/close` | acknowledge an incident (needs a `write` token) |

```
curl -H "Authorization: Bearer nsk_..." https://netsentinel.yourco.com:8777/api/v1/health
```

Tokens are stored as SHA-256 hashes, show once, carry a scope, record last use, can be
revoked, and every call is audited under `api:<token name>`.

**Host agent.** For machines where reachability is not enough:

```
run.bat --api-token-create agent-fleet --api-token-scope write      (on the console)
run.bat --agent --console https://netsentinel.yourco:8777 --token nsk_...
```

Thresholds live in Settings → *Host agent thresholds*. A host that stops reporting for
`stale_minutes` is flagged stale. The agent sends only the fields listed in its `collect()`
— no file names, no command lines, no user data.

**SIEM and chat.** Settings → *SIEM & chat alerts*: host, port, UDP/TCP, CEF or RFC 5424,
minimum severity; Slack and Teams webhook URLs. Press **Send test alert** and it reports
each channel separately. Example CEF line:

```
CEF:0|Prahari|Prahari|1.7|high|Kitchen AP is down|8|dvchost=Kitchen AP
  src=192.168.1.4 cs1Label=RootCause cs1=AP does not answer cs2Label=Category cs2=Wi-Fi
  cn1Label=Confidence cn1=75
```

**Publishing it on the internet.** The console is now safe to expose *behind something*:

```
run.bat --lan --tls --tls-cert C:\certs\chain.pem --tls-key C:\certs\key.pem ^
        --allow-cidr 10.0.0.0/8,203.0.113.0/24 --trusted-proxy 127.0.0.1 ^
        --sso-issuer https://login.microsoftonline.com/<tenant>/v2.0 --sso-client-id <id> ...
```

- **Allow-list first.** Anything outside it gets a 403 before authentication, and the
  attempt is logged.
- **Put a proxy in front.** nginx/Caddy/IIS terminates TLS on 443 and forwards to
  `127.0.0.1:8777`; list the proxy in `--trusted-proxy` so the real client address is used
  for audit and lockout. Never trust `X-Forwarded-For` from an unknown peer — the code
  ignores it unless the peer is listed.
- **Turn on 2FA for local accounts** (Users → 2FA) or switch to SSO only. Break-glass
  passwords without a second factor are how consoles get owned.
- **Watch the certificate.** `--cert-status` tells you the truth; the watcher emails you at
  21 days and can run `wacs.exe --renew --force` (or certbot) and restart.
- **Or skip all of it**: put the console on the VPN and never publish the port. That is
  still the best answer.

**Building the exe without a Windows PC.** Push this folder to a GitHub repository and run
the included workflow (`.github/workflows/build-windows-exe.yml`, *Actions → Build Windows
EXE → Run workflow*). It builds on `windows-latest` with PyInstaller, smoke-tests
`Prahari.exe --help`, and uploads the single-file exe as a downloadable artifact. That
is the only way to get a genuine Windows binary without a Windows machine — nothing on a
Linux or macOS box can cross-compile one, which is why the zip ships source plus the build
scripts.

**Signing and SBOM.**

```
python sbom.py            (writes sbom.json)
set PFX=C:\certs\netsentinel.pfx
set PFX_PASSWORD=...
sign_build.bat            (signs dist\*.exe and verifies)
```

A code-signing certificate is a purchase (OV or EV from a CA); nothing here can create one.

### What is still missing for a large enterprise

Being straight about the rest of the list, after 1.8: **no high availability or
clustering** (single process, SQLite, in-memory sessions — a warm standby is possible by
pointing a second console at the same branches, but there is no automatic failover), **no
LLDP/CDP topology map**, **no ServiceNow/ticketing connector** (SIEM, Slack, Teams, webhook
and REST are covered), **no built-in ACME client** (it drives win-acme/certbot instead of
re-implementing them), **no external penetration test or SOC 2 / ISO 27001 evidence**, and
**no support contract or vendor SLA**. Those last three are things you commission, not
things I can code.

## 9. Sign-in and security

- Sign-in turns on **automatically when the dashboard is bound to the LAN** (`--lan`),
  and can be forced with `--auth`. On localhost only it is off by default.
- The first run prints a generated `admin` password once. Change it in Settings, or run
  `run.bat --set-password YOURPASSWORD`.
- Passwords: PBKDF2-SHA256, 200 000 iterations, per-user salt. Sessions are random tokens
  in memory with an expiry; five wrong attempts lock that client out for ten minutes.
- Every state-changing POST needs the `X-NS` header (CSRF guard); frames are denied.
- Secrets (SMTP password, webhook URL) live in `%USERPROFILE%\.netsentinel\config.json`,
  written with owner-only permissions and masked in the dashboard.
- Nothing leaves the machine except: the public-IP lookup, optional email/webhook alerts,
  and the optional IEEE vendor list download.

---

## 10. Device identification

Scored from independent signals; the reason is shown per device.

| Device | Signals |
|---|---|
| **Router / firewall** | default gateway; DNS on 53; TR-069 7547; titles (`RouterOS`, `OpenWrt`, `Archer`, `DIR-`, ONT models); SNMP sysDescr; MAC vendor |
| **Switch** | SNMP 161; telnet 23; titles (`ProCurve`, `Catalyst`, `DGS-`, `TL-SG`, `EdgeSwitch`); bridge MIB answers |
| **Access point** | titles (`UniFi`, `AirOS`, `AeroNet`, `Aruba`, `Ruckus`, `Omada`); SSH+SNMP+HTTPS; MAC vendor |
| **KOT / receipt printer** | 9100, 515, 631; `Epson TM`, `TVS`, `Posiflex`, `Bixolon`, `Star Micronics`, `Rongta`, `Xprinter`, "thermal", "receipt", "KOT", "kitchen" |
| **Printer** | 9100/515/631/5357; `LaserJet`, `OfficeJet`, `Brother`, `Ricoh`, `Kyocera`, `Xerox`, `Pantum`, `JetDirect` |
| **Scanner** | 5357 WSD; `ScanSnap`, `CanonScan`, "scanner" |
| **DVR / NVR** | Dahua 37777, 34567, 6036; Hikvision 8000; RTSP 554; `Hikvision`, `Dahua`, `CP Plus`, `Uniview`, `XVR` |
| **IP camera** | RTSP 554 + camera banners |

Ports probed: 21 22 23 53 80 81 443 445 515 554 631 1883 3389 5000 5060 5357 5900 7547
8000 8001 8080 8081 8443 8888 9000 9100 34567 37777 6036 1935, plus UDP 161 (SNMP) and
137 (NetBIOS name).

---

## 11. Remote access

Each device row has a **remote** button: RDP (3389), VNC (5900), SSH (22), Telnet (23),
web admin page, RTSP live view in VLC, **Wake on LAN**, continuous ping. Prahari ships
no remote-desktop server of its own — it drives Windows' tools. To control a PC that has
none enabled, copy `enable_rdp.bat` to it and run it as Administrator once. Remote actions
run only from the PC hosting Prahari unless you start with `--allow-remote-control`.

---

## 12. Command line

```
run.bat                                  scan + monitor + console (normal use)
run.bat --lan                            shared on the LAN (sign-in required)
run.bat --poll-interval 30               poll every 30 s
run.bat --no-monitor                     discovery only, no polling/incidents
run.bat --auth / --no-auth               force / suppress sign-in
run.bat --set-password SECRET            set the admin password
run.bat --tls [--tls-cert PEM --tls-key PEM]   serve the console over HTTPS
run.bat --make-cert                      create a self-signed certificate
run.bat --sso-issuer URL --sso-client-id ID --sso-client-secret S --sso-redirect URL
run.bat --api-token-create NAME [--api-token-scope read|write]
run.bat --api-tokens                     list API tokens
run.bat --allow-cidr 10.0.0.0/8          only these networks may connect
run.bat --deny-cidr 203.0.113.9/32       block a network
run.bat --trusted-proxy 127.0.0.1        who may set X-Forwarded-For
run.bat --cert-status                    certificate expiry + renewal tool
run.bat --csr console.yourco.com         key + CSR for your own CA
run.bat --fleet-setup DIR --fleet-sites "A,B,C" --branch https://hub   per-site setup files
run.bat --fleet-setup DIR --fleet-csv sites.csv --branch https://hub   100 sites from a CSV
run.bat --heartbeat-url https://hc-ping.com/<uuid>   dead-man's switch
run.bat --branch auto                    use this PC's Tailscale address as the hub
run.bat --agent --console URL --token TOK   run as a host agent on this machine
run.bat --site-name "Head Office"        name this site
run.bat --hub                            this PC collects branch reports
run.bat --branch http://hub:8777 --token TOKEN   report this site to a hub
run.bat --new-branch-token "Branch 1"    issue a branch token and exit
run.bat --scan [--watch]                 one scan, print a report (optionally keep watching)
run.bat --scan --report report.txt       save the text report
run.bat --subnet 192.168.1.0/24          scan a different subnet
run.bat --shallow                        ping sweep + MAC only (fastest)
run.bat --no-capture                     never attempt packet capture
run.bat --no-remote-control              hide the remote buttons
run.bat --allow-remote-control           remote buttons from other devices too
run.bat --refresh-oui                    download the full IEEE vendor list
```

---

## 13. Settings file

`%USERPROFILE%\.netsentinel\config.json` — everything the Settings page edits, so you can
deploy it with a script or Group Policy:

```json
{
  "site_name": "Head Office",
  "poll_interval_seconds": 60,
  "thresholds": {"latency_warn_ms": 150, "latency_crit_ms": 300,
                 "loss_warn_pct": 3, "loss_crit_pct": 10,
                 "open_after_bad_polls": 2, "resolve_after_good_polls": 3},
  "monitor": {"printers": true, "phones": false, "unknown": false, "servers": true,
              "internet_targets": [{"name": "Internet - Google DNS", "host": "8.8.8.8"}]},
  "netflow": {"enabled": true, "port": 2055, "sflow_port": 6343, "allowed_exporters": []},
  "syslog": {"enabled": true, "port": 5514, "alert_patterns": ["(link|interface|port).{0,40}down"]},
  "email": {"enabled": false, "host": "smtp.zoho.in", "port": 465, "ssl": true,
            "username": "", "password": "", "from": "", "to": [], "min_severity": "medium"},
  "webhook": {"enabled": false, "url": "", "min_severity": "high"},
  "wan": {"interval_seconds": 600},
  "hub": {"enabled": false, "expect_minutes": 5, "sites": []},
  "branch": {"hub_url": "", "token": "", "interval_seconds": 30},
  "auth": {"enabled": false, "session_hours": 12}
}
```

History, incidents, events, users and labels live next to it in `netsentinel.db` (SQLite,
14 days of samples by default).

---

## 14. Troubleshooting

| Symptom | Fix |
|---------|-----|
| Traffic view says "no flow data" | Enable NetFlow/sFlow on the router and point it at this PC (section 4). Check the exporters list — if it is empty, nothing is arriving (firewall on the router side?). |
| No syslog events | Point the firewall at UDP 5514; confirm the port is not already taken (`--no-monitor` then check the console line). |
| Emails not arriving | Settings → Send test alert tells you the exact SMTP error. Zoho/Gmail need an app password, not your login password. |
| Everything shows "unknown" state | Monitoring is off (`--no-monitor`) or the devices are types that are not polled by default — see Settings. |
| Incident opens and closes repeatedly | Thresholds too tight for Wi-Fi. Raise `latency_warn_ms` or `open_after_bad_polls`. |
| Only 1 device found | The PC may be on a `/32` or captive-portal Wi-Fi; use `--subnet`. |
| Forgot the password | `run.bat --set-password NEWPASSWORD` on that PC. |
| Dashboard won't open | It auto-tries 8777–8788; the console prints the real URL. |
| Ports already in use | Change `netflow`/`syslog` ports in Settings, or start with `--port`. |

---

## 15. Honest limits

- Diagnosis is rule-based, not omniscient: confidence is shown, and the missing-data list
  tells you which collector would sharpen it.
- Per-device internet usage needs flow export (or SNMP/capture). Without one of them you
  see device health but not who is streaming video.
- DVR and NVR are indistinguishable from the network; those rows say "DVR / NVR (recorder)".
- Wi-Fi client counts and per-SSID usage need the AP's own SNMP/API — the AP is identified
  and polled, but its client table is not read.
- A subnet larger than /22 is truncated to the first 1024 addresses.
- Alert delivery depends on your SMTP server; the dashboard logs every send attempt.
- Branch reporting needs a route from the branch to the hub (VPN or port-forward).
  The hub is a collector, not a relay: there is no hosted relay service in the middle,
  and branches keep working on their own if the hub is unreachable.
- Availability percentages come from the poll history (14 days kept by default), so a
  report for 30 days only covers the days Prahari was actually running.

---

## Files

```
Prahari/
├─ Build-Setup-EXE.bat            build the single-file installer (zero downloads)
├─ bootstrap.cmd                  the installer logic: app + Python + extras + shortcuts
├─ uninstall.cmd                  remove it (/purge = also config and history)
├─ sign_build.bat                 sign the built exe with your certificate
├─ sbom.py / sbom.json            software bill of materials for a security review
├─ EULA.txt                       licence to start from before distributing
├─ netsentinel.ico                application icon
├─ run.bat / install.bat          normal start / one-time setup
├─ dashboard_lan.bat              share the console on the LAN (sign-in on)
├─ open_dashboard.bat             reopen the console page
├─ allow_firewall.bat             firewall rule for LAN access (admin)
├─ autostart_install.bat / _remove.bat
├─ enable_rdp.bat                 enable Remote Desktop on a target PC (admin)
├─ build_exe.bat                  single-file .exe build
├─ requirements.txt               two optional extras (scapy, psutil)
├─ netsentinel.py                 entry point / CLI
└─ netscan/
   ├─ netinfo.py       local IP, subnet, gateway, DNS, public IP, ARP
   ├─ discovery.py     ping sweep, port scan, HTTP/RTSP/NetBIOS/SNMP probes
   ├─ fingerprint.py   device classification rules and scoring
   ├─ snmp.py          minimal SNMPv2c client (no dependencies)
   ├─ netflow.py       NetFlow v5/v9 + sFlow parsers and collector
   ├─ syslogrx.py      syslog receiver and alert patterns
   ├─ poll.py          monitoring engine, state machine, incidents
   ├─ diagnose.py      rule-based root-cause diagnosis
   ├─ alerts.py        SMTP email + JSON webhook
   ├─ auth.py          users, roles, sessions, lockout
   ├─ oidc.py          OpenID Connect SSO (PKCE, JWKS, RS256, role mapping)
   ├─ tlsutil.py       HTTPS certificates and the TLS context
   ├─ apitokens.py     REST API tokens with scopes
   ├─ agent.py         host agent: CPU, memory, disk, services
   ├─ netguard.py      client address, trusted proxies, allow/deny lists
   ├─ totp.py          RFC 6238 two-factor for local accounts
   ├─ certs.py         certificate expiry watch, renewal hook, CSR
   ├─ heartbeat.py     dead-man's switch to an outside service
   ├─ fleet.py         per-site setup files and tokens for a chain
   ├─ tailnet.py       Tailscale detection for free remote access
   ├─ wan.py           public IP / ISP tracking, dual-WAN detection
   ├─ sites.py         branch reporting, hub aggregation, lost-contact alerts
   ├─ settings.py      config.json load/save with defaults
   ├─ store.py         SQLite: samples, incidents, events, users, labels
   ├─ scanner.py       orchestration and live state
   ├─ remote.py        RDP / VNC / SSH / web / RTSP / wake-on-LAN
   ├─ webui.py         the six-view console (stdlib http.server)
   ├─ report.py        text report
   ├─ monitor.py       SNMP counters, passive capture, NIC rates
   ├─ oui.py           MAC vendor lookup
   └─ version / init
```
