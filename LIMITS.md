# Prahari — known limits, stated plainly

A tool that hides its limits is worse than one that does not have them. Everything below is
true of this release as shipped. Where a limit is a choice it says so; where something is
untested it says that too. (Adapted from the parallel Prahari copy's list and corrected for Prahari.)

---

## 1. What is proven, and how

Every build runs an automated test suite on a real Windows machine (GitHub Actions) before the
exe is made; one failure stops the release. Run it yourself: `python -m unittest discover -s tests -t .`

| Area | Proven against |
|---|---|
| `Prahari.exe` build | built and started on Windows for every release |
| Signed self-update of the exe | the real exe replaces itself while running and refuses a tampered release (Windows) |
| Signed update of source installs, rollback, hub fleet update | local signed releases, broken and failing builds |
| Windows sign-in | real Windows administrator and standard accounts created on the build machine |
| Sign-in lockout, secret masking, CSRF guard, dashboard JavaScript | the running console over HTTP |
| Claude diagnosis and Ask AI | a fake API (fallback on refusal, errors, limits) — no real API call in the tests |
| Factory-password check | fake web servers and cameras on the build machine |
| Backup restore | a live database with unsaved write-ahead-log data |
| SNMPv3 key derivation | the RFC 3414 published test vectors |
| UDP service probes (NTP, NetBIOS, SNMP, UPnP, mDNS) | fake services on the build machine; mDNS also seen on a real office LAN |
| Sensors (http, tcp, dns, cert incl. self-signed, snmp thresholds), quiet hours, dependencies | local web, HTTPS and fake SNMP services on the build machine |
| Head-office update mirror | a real hub console + a branch copy: publish, token-only download, unsigned/tampered refused at the hub and at the branch |
| Sensor history and retention, service/process checks, Wall map | the test suite and a browser render of every tab (no page errors) |
| SLA PDF | generated and checked |

## 2. What has never run on real equipment

| Area | Not yet proven on |
|---|---|
| SNMPv3, topology map (LLDP/CDP), Wi-Fi counters | real switches and access points |
| Factory-password check | real recorders and cameras (Hikvision, Dahua, CP Plus login paths differ) |
| Windows installer scripts (`bootstrap.cmd`, `install.bat`, Tailscale MSI, Npcap) | a real hotel PC |
| Claude diagnosis | your API key on a real incident (use *Test the key* in Settings first) |

The first month on a real network will find things. Report them; each one becomes a test.

---

## 3. Choices, not bugs

- **The exe is not code-signed.** Windows SmartScreen shows "Windows protected your PC" until a
  code-signing certificate is bought. Updates are signed separately (Ed25519) and verified.
- **The hub is one PC.** No clustering. Branches keep monitoring and queue alerts if the hub
  dies; the outside heartbeat tells you it went dark.
- **SQLite, not a server database.** Measured fine at 100 sites; not for thousands.
- **No config backup or drift detection**, no vendor APIs (UniFi, Omada, Aruba Central) —
  standard SNMP only. No deep packet inspection, by design.
- **"Who is using the internet" needs flow export from the router**; without it the console
  says `source: none` rather than inventing numbers.
- **Sessions live in memory.** A restart or an update signs everyone out.
- **English only.**

## 4. Things that behave differently than you might assume

- **Sign-in is always required**, on the PC too. Windows administrators of the PC can sign in
  with their Windows password; other Windows users are refused unless Settings allows a lower role.
- **Anomaly detection needs 14 days of history** and stays silent until then.
- **The factory-password check cannot test form logins.** Those devices are reported as
  "verify by hand", never as pass or fail. It only touches private LAN addresses on its
  allow-list, and some devices may still count failed logins — run it out of hours first.
- **PoE power-cycling exists but nothing triggers it automatically yet.** It is dry-run until
  set live, private-LAN only, inside a maintenance window, rate-limited.
- **Claude sends data out only when switched on.** Then each incident's evidence and each
  question go to Anthropic's API under your key. Off by default.
- **Updates are checked on GitHub every 6 hours** (Settings → Updates to turn off). Only
  releases signed with the Prahari key install; a version that fails to start is rolled back.
- **Email needs an app password** (Gmail, Zoho, Outlook refuse normal passwords from scripts).
- **Nothing inside a building can report that the building is offline** — that is what the
  free healthchecks.io heartbeat is for.

## 5. Security of Prahari itself

- **TLS is opt-in.** Without `--tls` the console speaks plain HTTP on your LAN.
- **Secrets are encrypted at rest only if `cryptography` is installed** (it is bundled in the exe).
  The dashboard never sends a secret back to any browser.
- **API tokens are bearer tokens** — scoped and hashed at rest; revoke a leaked one.
- **The event log is operational, not evidence** — an administrator can edit the database.
- **No external penetration test has been done.**

### Security review (1.37.2): what holds, and where it could be compromised

| What holds | How |
|---|---|
| Passwords | PBKDF2-SHA256 with a per-user salt; Windows sign-in stores nothing. Repeated wrong passwords lock the address out. |
| Sessions | Random tokens, `HttpOnly; SameSite=Strict`, `Secure` with TLS; sign-out ends them. |
| Cross-site requests | Every state-changing request needs the `X-NS` header, which another website cannot set. |
| SQL | Every query is parameterised. |
| Secrets at rest | Encrypted (AES-GCM) with a key file readable only by the service. |
| Tokens | Branch, API and organisation tokens are stored hashed and compared in constant time. |
| Updates | Only signed releases install (Ed25519 signature + SHA-256); a bad update rolls back. |
| Request size | Anything over 2 MB is refused before it is read (1.38.0). |
| User names | A wrong user name takes as long to refuse as a wrong password (1.38.0). |
| No shell | Nothing from a request or a setting reaches a shell. Since 1.37.2 the certificate-renewal command is split into program + arguments and refuses shell syntax (`` ; \| & < > $ ` % ^ ``). Sensors and config backup pass values only as quoted arguments. |

Where it could be compromised, worst first, and how to close it:

1. **The dashboard reachable from the internet** (port-forwarded, or `--lan` on a public address).
   Passwords and lock-out slow an attacker down; they do not stop one. Keep it on the LAN and
   reach it over the VPN; turn on `--tls` and an allow-list (Settings -> Access).
2. **Prahari runs as SYSTEM** (the background service). Any flaw that lets someone run code in
   Prahari gives them the whole PC. Keep the Prahari PC patched and limit who is a Prahari admin.
3. **Who can change Settings controls what Prahari does to devices.** The factory-password check,
   PoE remediation and config backup act on your devices; they are limited to private LAN
   addresses, allow-lists and an audit trail, but a stolen admin login could still aim them at
   other devices on the LAN. Leave them off until you need them; keep 2FA on for admins.
4. **Reports to a self-hosted hub over plain HTTP** carry the branch token in a header.
   Reports to the Prahari portal always use HTTPS. For your own hub, use `--tls` and `https://`.
5. **The Prahari portal account.** The organisation key and the Update button live there; protect
   the owner's email account, which is how portal sign-in is confirmed.
6. **Server health over SNMP (Systems tab)** uses SNMP v1/v2c communities, which travel in clear
   text on the LAN. Give servers a read-only community that is not `public`, accept only the
   Prahari PC in the SNMP service, or use SNMPv3 (Settings -> SNMPv3). Proven: parsing with
   recorded Windows/Linux answers and this PC's own numbers. Not yet proven against a real
   Windows server's SNMP service.
7. **Third-party packages** (`cryptography`, `psutil`, the Anthropic SDK) are bundled in the exe
   and listed in `sbom.json`; nothing is downloaded at run time except signed updates.

## 6. Legal and ethical bounds

The port scan, posture checks and factory-password check are for networks you own or
administer (EULA section 7). The hardening plan is advice: closing a port can break a device —
test on one site before a hundred.

## 7. Missing outright

| Missing | What to do |
|---|---|
| Code-signing certificate | buy one, then `sign_build.bat` |
| External penetration test | hire a tester; give them this file first |
| High availability | keep the heartbeat on and the database backed up |
| Config backup / drift, SNMPv3 SET, native mobile app | not built — the console installs as a phone app (PWA) |
| Support contract with an SLA | a separate agreement |

*If a limit here matters to you, name it. A named gap is cheaper to close than a general worry.*
