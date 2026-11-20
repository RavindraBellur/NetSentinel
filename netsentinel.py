#!/usr/bin/env python3
"""Prahari - find every device on your LAN, then show who is using the internet.

Run with no arguments on Windows (double click run.bat): it scans the network it
is plugged into and opens a dashboard at http://127.0.0.1:8777 .

    python netsentinel.py                 scan, then serve the dashboard
    python netsentinel.py --scan          one-shot scan, print a report, exit
    python netsentinel.py --scan --watch  scan, then keep printing live traffic
    python netsentinel.py --serve         dashboard only (no immediate scan)
    python netsentinel.py --subnet 192.168.1.0/24
    python netsentinel.py --no-capture    skip packet capture entirely
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netscan import __version__, apitokens, auth, netinfo, oui, settings, sites, store  # noqa: E402
from netscan import certs as certs_mod, fleet as fleet_mod, tailnet, tlsutil  # noqa: E402
from netscan import scanner as scanner_mod, webui  # noqa: E402
from netscan import agent as agent_mod, updater as updater_mod  # noqa: E402
from netscan.report import text_report  # noqa: E402


def banner():
    print("=" * 62)
    print(f" Prahari {__version__}  -  LAN devices + bandwidth monitor")
    print("=" * 62)


def do_scan(args, sc):
    sc.start_scan()
    last_msg = ""
    while True:
        snap = sc.snapshot()
        st = snap["status"]
        msg = st.get("message", "")
        if msg != last_msg:
            print("  " + msg)
            last_msg = msg
        if not st.get("scan_running"):
            break
        time.sleep(0.4)
    snap = sc.snapshot()
    print()
    print(text_report(snap))
    return snap


def start_auto_rescan(sc, seconds):
    """Keep the dashboard fresh: rescan quietly in the background."""

    def loop():
        while True:
            time.sleep(max(30, seconds))
            try:
                if not sc.snapshot()["status"].get("scan_running"):
                    sc.start_scan()
            except Exception:
                pass

    threading.Thread(target=loop, daemon=True, name="auto-rescan").start()


def main(argv=None):
    parser = argparse.ArgumentParser(description="LAN device discovery and bandwidth monitor")
    parser.add_argument("--scan", action="store_true", help="scan once, print report, exit")
    parser.add_argument("--serve", action="store_true", help="start the dashboard without scanning first")
    parser.add_argument("--watch", action="store_true", help="keep running and print live traffic")
    parser.add_argument("--subnet", help="scan this subnet instead of the auto-detected one (e.g. 192.168.1.0/24)")
    parser.add_argument("--port", type=int, default=8777, help="dashboard port (default 8777)")
    parser.add_argument("--host", default="127.0.0.1", help="bind address (0.0.0.0 = reachable from other devices)")
    parser.add_argument("--lan", action="store_true", help="same as --host 0.0.0.0: open the dashboard from your laptop/phone")
    parser.add_argument("--no-browser", action="store_true", help="do not open the dashboard window")
    parser.add_argument("--browser", action="store_true", help="open in a normal browser tab instead of an app window")
    parser.add_argument("--rescan-every", type=int, default=600, metavar="SECONDS",
                        help="re-scan the network automatically (0 = never, default 600)")
    parser.add_argument("--monitor", action="store_true", default=None,
                        help="continuous monitoring (default on): poll devices, open incidents, alert")
    parser.add_argument("--no-monitor", action="store_true", help="discovery only, no polling/incidents")
    parser.add_argument("--poll-interval", type=int, help="poll every N seconds (default 60)")
    parser.add_argument("--auth", action="store_true", help="require sign-in for the dashboard")
    parser.add_argument("--no-auth", action="store_true",
                        help="do not require sign-in even when shared on the LAN (not recommended)")
    parser.add_argument("--set-password", metavar="PASSWORD", help="set the admin password and exit")
    parser.add_argument("--allow-remote-control", action="store_true",
                        help="allow the dashboard to start remote sessions from other devices (not just this PC)")
    parser.add_argument("--no-remote-control", action="store_true",
                        help="disable the remote-access buttons completely")
    parser.add_argument("--no-capture", action="store_true", help="do not use packet capture for traffic")
    parser.add_argument("--shallow", action="store_true", help="ping sweep + MAC only (fast, less detail)")
    parser.add_argument("--community", default="public", help="SNMP community string to try (default public)")
    parser.add_argument("--site-name", metavar="NAME", help="name of this site (shown in the console and to the hub)")
    parser.add_argument("--hub", action="store_true", help="this PC is the head office hub: collect branch reports")
    parser.add_argument("--branch", metavar="URL",
                        help="report this site to a hub, e.g. http://10.0.0.5:8777 "
                             "(or 'auto' to use this PC's Tailscale address)")
    parser.add_argument("--token", metavar="TOKEN", help="branch token issued by the hub")
    parser.add_argument("--new-branch-token", metavar="NAME",
                        help="create a token for a branch called NAME and exit")
    parser.add_argument("--tls", action="store_true", help="serve the console over HTTPS")
    parser.add_argument("--tls-cert", metavar="PEM", help="certificate chain (PEM) from your PKI")
    parser.add_argument("--tls-key", metavar="PEM", help="private key (PEM) for the certificate")
    parser.add_argument("--make-cert", action="store_true",
                        help="create a self-signed certificate for --tls and exit")
    parser.add_argument("--sso-issuer", metavar="URL", help="OpenID Connect issuer, e.g. https://login.microsoftonline.com/<tenant>/v2.0")
    parser.add_argument("--sso-client-id", metavar="ID", help="OIDC application (client) id")
    parser.add_argument("--sso-client-secret", metavar="SECRET", help="OIDC client secret")
    parser.add_argument("--sso-redirect", metavar="URL", help="redirect URI registered at the provider")
    parser.add_argument("--sso-domains", metavar="LIST", help="comma separated email domains allowed to sign in")
    parser.add_argument("--sso-role-map", metavar="GROUP=ROLE,...",
                        help="map provider groups to roles, e.g. net-admins=admin,net-techs=engineer")
    parser.add_argument("--allow-cidr", metavar="LIST",
                        help="only allow these networks, e.g. 10.0.0.0/8,203.0.113.0/24")
    parser.add_argument("--deny-cidr", metavar="LIST", help="block these networks")
    parser.add_argument("--trusted-proxy", metavar="LIST",
                        help="reverse proxies allowed to set X-Forwarded-For (default 127.0.0.1)")
    parser.add_argument("--csr", metavar="DOMAIN",
                        help="generate a key + CSR for your CA to sign, then exit")
    parser.add_argument("--cert-status", action="store_true",
                        help="show the certificate expiry and the detected renewal tool, then exit")
    parser.add_argument("--fleet-setup", metavar="DIR",
                        help="write one-click setup files for a chain of sites into DIR and exit")
    parser.add_argument("--restore", metavar="FILE",
                        help="restore a database backup (needs --confirm)")
    parser.add_argument("--confirm", action="store_true",
                        help="really do it (for --restore)")
    parser.add_argument("--backups", action="store_true", help="list the database backups")
    parser.add_argument("--sla-fleet", metavar="DIR", nargs="?", const="reports",
                        help="one PDF per hotel, from the reports the branches send")
    parser.add_argument("--sla-report", metavar="SITE", nargs="?", const="",
                        help="write the monthly service report as a PDF and exit")
    parser.add_argument("--sla-month", metavar="YYYY-MM",
                        help="which month for --sla-report (default: last month)")
    parser.add_argument("--sla-out", metavar="DIR", default="reports",
                        help="where to write the PDF (default: ./reports)")
    parser.add_argument("--fleet-csv", metavar="FILE",
                        help="CSV of name,region,email for a large roll-out (header optional)")
    parser.add_argument("--fleet-emails", metavar="LIST",
                        help='IT managers per site: "Udaipur=it@x.com,gm@x.com;Goa=it@y.com"')
    parser.add_argument("--fleet-tailscale-key", metavar="KEY",
                        help="auth key embedded in each site's setup so Tailscale installs itself")
    parser.add_argument("--fleet-sites", metavar="LIST",
                        help="site names for --fleet-setup, comma separated")
    parser.add_argument("--install-tailscale", action="store_true",
                        help="download and install Tailscale silently, then join the tailnet")
    parser.add_argument("--tailscale-key", metavar="KEY",
                        help="Tailscale auth key (tskey-...) used to join without a browser")
    parser.add_argument("--tailscale-name", metavar="NAME",
                        help="host name for this PC on the tailnet, e.g. udaipur-reception")
    parser.add_argument("--heartbeat-provision", metavar="APIKEY",
                        help="create one healthchecks.io check per site and store the URLs")
    parser.add_argument("--heartbeat-url", metavar="URL",
                        help="dead-man's-switch URL pinged every few minutes (healthchecks.io etc.)")
    parser.add_argument("--api-token-create", metavar="NAME", help="create an API token and exit")
    parser.add_argument("--api-token-scope", default="read", choices=["read", "write"],
                        help="scope for --api-token-create (default read)")
    parser.add_argument("--api-tokens", action="store_true", help="list API tokens and exit")
    parser.add_argument("--agent", action="store_true",
                        help="run as a host agent: report CPU/memory/disk/services to a console")
    parser.add_argument("--console", metavar="URL", help="console URL for --agent, e.g. https://10.0.0.5:8777")
    parser.add_argument("--agent-interval", type=int, default=60, metavar="SECONDS",
                        help="how often the agent reports (default 60)")
    parser.add_argument("--insecure", action="store_true",
                        help="agent: accept a self-signed console certificate")
    parser.add_argument("--refresh-oui", action="store_true", help="download the IEEE vendor registry and exit")
    parser.add_argument("--report", metavar="FILE", help="write the text report to FILE")
    parser.add_argument("--check-update", action="store_true",
                        help="check GitHub for a newer Prahari and exit")
    parser.add_argument("--update-now", action="store_true",
                        help="download and install the newest Prahari, then exit (start it again after)")
    parser.add_argument("--selftest-update", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--limits", action="store_true", help="print the known limits of this build and exit")
    args = parser.parse_args(argv)

    if args.selftest_update:
        return updater_mod.selftest()

    if args.limits:
        for base in (os.path.dirname(os.path.abspath(__file__)), getattr(sys, "_MEIPASS", "")):
            lp = os.path.join(base, "LIMITS.md") if base else ""
            if lp and os.path.exists(lp):
                with open(lp, encoding="utf-8") as fh:
                    print(fh.read())
                return 0
        print("LIMITS.md is not installed next to this program")
        return 1

    if args.check_update or args.update_now:
        upd = updater_mod.Updater(lambda: settings.get("update"), log=lambda m: print("  " + m))
        restart = upd.check_once(install=bool(args.update_now))
        snap = upd.snapshot()
        print(f"  this copy   : {snap['version']} ({snap['mode']} install)")
        print(f"  newest      : {snap['latest'] or 'unknown'}")
        if snap["error"]:
            print(f"  problem     : {snap['error']}")
        elif restart:
            print(f"  installed {snap['latest']} - start Prahari again to run it")
        elif snap["status"] == "available":
            print("  an update is available: run with --update-now"
                  if snap["can_install"] else f"  download it from {snap['notes_url']}")
        else:
            print("  up to date")
        return 1 if snap["status"] == "error" else 0

    if args.set_password:
        if store.user_count():
            store.set_password("admin", args.set_password)
        else:
            store.create_user("admin", args.set_password, "admin")
        print("  admin password updated")
        return 0

    if args.agent:
        console = args.console or (settings.get("agent") or {}).get("console") or ""
        token = args.token or (settings.get("agent") or {}).get("token") or ""
        if not console or not token:
            print("  --agent needs a console URL and a token:")
            print("    run.bat --agent --console https://10.0.0.5:8777 --token nsk_...")
            print("  Create the token on the console with: run.bat --api-token-create <name> --api-token-scope write")
            return 1
        settings.save({"agent": {"console": console, "token": token}})
        banner()
        print(f"  agent       : {socket.gethostname()}")
        print(f"  console     : {console}")
        print(f"  interval    : {args.agent_interval}s")
        worker = agent_mod.Agent(console, token, args.agent_interval,
                                 log=lambda m: print("  " + m), verify_tls=not args.insecure)
        ok = worker.push()
        print(f"  first report: {'sent' if ok else 'FAILED - ' + (worker.last_error or 'unknown')}")
        if not ok:
            return 1
        worker.start()
        try:
            while True:
                time.sleep(30)
                print(f"  reports sent: {worker.sent}"
                      + (f"  last error: {worker.last_error}" if worker.last_error else ""))
        except KeyboardInterrupt:
            worker.stop()
            print("\n  agent stopped")
        return 0

    if args.install_tailscale:
        banner()
        ok, msg = tailnet.install(log=lambda m: print(m))
        print(f"  install     : {msg}")
        if not ok:
            return 1
        if args.tailscale_key:
            ok, msg = tailnet.join(args.tailscale_key, args.tailscale_name or "",
                                   log=lambda m: print(m))
            print(f"  join        : {msg}")
            if not ok:
                return 1
            settings.save({"tailscale": {"joined": True,
                                         "name": args.tailscale_name or ""}})
        else:
            print("  no --tailscale-key given: Tailscale is installed but not joined.")
            print("  Create a key at https://login.tailscale.com/admin/settings/keys and run:")
            print("    run.bat --install-tailscale --tailscale-key tskey-...")
        return 0

    if args.fleet_setup:
        site_rows = fleet_mod.read_csv(args.fleet_csv) if args.fleet_csv else None
        names = [n.strip() for n in (args.fleet_sites or "").split(",") if n.strip()]
        if site_rows:
            names = [r["name"] for r in site_rows]
        if not names:
            print("  give the site names:  --fleet-sites \"Udaipur,Jaipur,Mount Abu\"")
            return 1
        hub = args.branch or (settings.get("hub") or {}).get("public_url") or ""
        if not hub or hub.strip().lower() in ("auto", "tailscale", "tailnet"):
            resolved = tailnet.best_url(8777) or ""
            if not resolved:
                print("  no hub address: install Tailscale (free) and run 'tailscale up',")
                print("  then use --branch auto, or give --branch http://ip:8777")
                return 1
            hub = resolved
            print(f"  hub resolved from Tailscale: {hub}")
        if not hub:
            print("  give the hub address every site will report to:  --branch https://hub.example.com")
            return 1
        made, summary = fleet_mod.build(names, hub, args.fleet_setup,
                                        ts_key=args.fleet_tailscale_key or "",
                                        emails=fleet_mod.parse_emails(args.fleet_emails or ""),
                                        site_rows=site_rows)
        print(f"  hub        : {hub}")
        print(f"  {len(made)} site(s) prepared in {args.fleet_setup}")
        print()
        for item in made:
            print(f"   {item['name']:<22} setup-{fleet_mod.slug(item['name'])}.cmd")
            print(f"   {'':<22} token {item['token']}")
        print()
        print(f"  summary: {summary}")
        print("  Copy each site's folder to that hotel and run setup-<site>.cmd there.")
        return 0

    if args.backups:
        from netscan import backup as backup_mod
        items = backup_mod.listing(50)
        if not items:
            print("  no backups yet")
        for item in items:
            print(f"  {item['name']:<40} {item['bytes']/1024:8.0f} KB  "
                  f"{time.strftime('%d/%m/%Y %H:%M', time.localtime(item['when']))}")
        return 0

    if args.restore:
        from netscan import backup as backup_mod
        ok, msg = backup_mod.restore(args.restore, confirm=args.confirm)
        print(("  " if ok else "  failed: ") + msg)
        return 0 if ok else 1

    if args.sla_fleet is not None:
        from netscan import sla as sla_mod
        files = sla_mod.fleet(out_dir=args.sla_fleet, month=args.sla_month or None)
        if not files:
            print("  no hotel has sent a summary yet (run this on the hub)")
            return 1
        for f in files:
            print(f"  written: {f}")
        return 0

    if args.sla_report is not None:
        from netscan import sla as sla_mod
        try:
            path = sla_mod.render(args.sla_month or None, site=args.sla_report or None,
                                  out_dir=args.sla_out)
        except Exception as exc:
            print(f"  report failed: {exc}")
            return 1
        print(f"  written: {path}")
        return 0

    if args.heartbeat_provision:
        from netscan import heartbeat as hb_mod
        names = [n["name"] for n in (settings.get("hub") or {}).get("sites") or []]
        if not names:
            names = [settings.get("site_name") or "this-site"]
        print(f"  creating {len(names)} check(s) at healthchecks.io ...")
        try:
            made = hb_mod.provision(args.heartbeat_provision, names)
        except Exception as exc:
            print(f"  failed: {exc}")
            print("  (the free plan allows 20 checks - use one check for the hub instead)")
            return 1
        cfg = settings.load()
        hub = dict(cfg.get("hub") or {})
        rows = []
        for entry in hub.get("sites") or []:
            entry = dict(entry)
            if entry.get("name") in made:
                entry["heartbeat_url"] = made[entry["name"]]
            rows.append(entry)
        hub["sites"] = rows
        settings.save({"hub": hub})
        for name, url in made.items():
            print(f"   {name:<32} {url}")
        print("  Stored on each site. Regenerate that site's setup-<site>.cmd to pick it up.")
        return 0

    if args.heartbeat_url:
        settings.save({"heartbeat": {"enabled": True, "url": args.heartbeat_url}})
        print(f"  heartbeat every {settings.get('heartbeat', 'interval_seconds')}s to {args.heartbeat_url}")

    if args.csr:
        try:
            csr_path, key_path = certs_mod.make_csr(args.csr)
        except Exception as exc:
            print(f"  could not create the CSR: {exc}")
            return 1
        print(f"  CSR  : {csr_path}")
        print(f"  key  : {key_path}")
        print("  Give the .csr to your certificate authority, then point")
        print("  --tls-cert at the signed certificate and --tls-key at this key.")
        return 0

    if args.cert_status:
        tls_cfg = settings.get("tls") or {}
        cert = args.tls_cert or tls_cfg.get("cert") or tlsutil.DEFAULT_CERT
        info = certs_mod.expiry_info(cert)
        if not info:
            print(f"  no readable certificate at {cert}")
        else:
            print(f"  certificate : {cert}")
            print(f"  subject     : {info['subject']}")
            print(f"  issuer      : {info['issuer']}{'  (self-signed)' if info['self_signed'] else ''}")
            print(f"  expires     : {info['not_after']}  ({info['days_left']} days left)")
        tool, path = certs_mod.find_renewal_tool()
        print(f"  renewal tool: {tool + ' at ' + path if tool else 'none found (win-acme or certbot)'}")
        cmd = (settings.get("certs") or {}).get("renew_command")
        print(f"  renew command: {cmd or 'not configured'}")
        return 0

    if args.make_cert:
        try:
            cert, key = tlsutil.make_self_signed()
        except Exception as exc:
            print(f"  could not create a certificate: {exc}")
            return 1
        info = tlsutil.describe(cert)
        print(f"  certificate: {cert}")
        print(f"  private key: {key}")
        print(f"  subject    : {info['subject'] or 'n/a'}")
        print(f"  covers     : {', '.join(info['san']) or 'n/a'}")
        print("  Browsers will warn until this certificate is trusted; for a real deployment use")
        print("  --tls-cert/--tls-key with a certificate from your own PKI.")
        return 0

    if args.api_token_create:
        token = apitokens.create(args.api_token_create, args.api_token_scope)
        print()
        print("  " + "=" * 62)
        print(f"   API token '{args.api_token_create}' (scope {args.api_token_scope})")
        print(f"   {token}")
        print("   Copy it now - only its hash is stored.")
        print("   Use it as:  Authorization: Bearer <token>")
        print("  " + "=" * 62)
        return 0

    if args.api_tokens:
        rows = apitokens.listing()
        if not rows:
            print("  no API tokens")
        for row in rows:
            used = row.get("last_used_ts")
            print(f"  {row['id']:>3}  {row['name']:<28} {row['scope']:<6} "
                  f"created {row['created_ts']}  last used {used or 'never'}")
        return 0

    if args.allow_cidr or args.deny_cidr or args.trusted_proxy:
        patch = {"access": {}}
        if args.allow_cidr:
            patch["access"]["allow_cidrs"] = [x.strip() for x in args.allow_cidr.split(",") if x.strip()]
        if args.deny_cidr:
            patch["access"]["deny_cidrs"] = [x.strip() for x in args.deny_cidr.split(",") if x.strip()]
        if args.trusted_proxy:
            patch["access"]["trusted_proxies"] = [x.strip() for x in args.trusted_proxy.split(",") if x.strip()]
        settings.save(patch)
        print("  access control: " + ", ".join(f"{k}={v}" for k, v in patch["access"].items()))

    if args.tls or args.tls_cert or args.tls_key:
        settings.save({"tls": {"enabled": True,
                               "cert": args.tls_cert or settings.get("tls", "cert") or "",
                               "key": args.tls_key or settings.get("tls", "key") or ""}})
    if args.sso_issuer:
        role_map = {}
        if args.sso_role_map:
            for pair in args.sso_role_map.split(","):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    role_map[k.strip()] = v.strip()
        patch = {"oidc": {"enabled": True, "issuer": args.sso_issuer,
                          "client_id": args.sso_client_id or settings.get("oidc", "client_id") or "",
                          "redirect_uri": args.sso_redirect or settings.get("oidc", "redirect_uri") or ""}}
        if args.sso_client_secret:
            patch["oidc"]["client_secret"] = args.sso_client_secret
        if args.sso_domains:
            patch["oidc"]["allowed_domains"] = [d.strip() for d in args.sso_domains.split(",") if d.strip()]
        if role_map:
            patch["oidc"]["role_map"] = role_map
        settings.save(patch)
        print("  SSO configured: " + args.sso_issuer)

    if args.site_name:
        settings.save({"site_name": args.site_name})
        print(f"  site name set to: {args.site_name}")
    if args.hub:
        settings.save({"hub": {"enabled": True}})
        print("  hub mode on: this PC will collect branch reports")
    if args.branch:
        hub = args.branch
        if hub.strip().lower() in ("auto", "tailscale", "tailnet"):
            hub = tailnet.best_url(8777)
            if not hub:
                print("  no Tailscale address found - install Tailscale (free) and run 'tailscale up',")
                print("  or give the hub address explicitly with --branch http://ip:8777")
                return 1
            print(f"  using this PC's Tailscale address as the hub: {hub}")
        settings.save({"branch": {"hub_url": hub.rstrip("/")}})
        print(f"  reporting to hub: {args.branch}")
    if args.token:
        settings.save({"branch": {"token": args.token}})
        print("  branch token saved")
    if args.new_branch_token:
        name = args.new_branch_token.strip()[:64]
        token = sites.new_token()
        cfg = settings.load()
        hub = dict(cfg.get("hub") or {})
        rows = [x for x in (hub.get("sites") or []) if x.get("name") != name]
        rows.append({"name": name, "token_hash": sites.token_hash(token),
                     "created_ts": int(__import__("time").time())})
        hub["sites"] = rows
        hub.setdefault("enabled", True)
        settings.save({"hub": hub})
        print()
        print("  " + "=" * 60)
        print(f"   Branch token for '{name}' (copy it now, it is not shown again)")
        print(f"   {token}")
        print()
        print(f"   On that branch run:  run.bat --branch http://<this-pc-ip>:8777 --token {token}")
        print("  " + "=" * 60)
        return 0

    if args.poll_interval:
        settings.save({"poll_interval_seconds": max(15, args.poll_interval)})

    if args.refresh_oui:
        banner()
        ok, msg = oui.refresh_oui()
        print(("  vendor registry updated: " if ok else "  could not update registry: ") + msg)
        return 0 if ok else 1

    if not args.scan and updater_mod.boot_check(log=lambda m: print("  " + m)):
        # the update failed to start several times and the previous version is back: run that one
        updater_mod.spawn(updater_mod.relaunch_cmd())
        return 1

    banner()

    sc = scanner_mod.Scanner(
        subnet=args.subnet,
        community=args.community,
        deep=not args.shallow,
        capture=not args.no_capture,
        allow_remote_control=args.allow_remote_control,
        remote_control=not args.no_remote_control,
        monitoring=not args.no_monitor,
    )

    if args.scan:
        snap = do_scan(args, sc)
        if args.report:
            with open(args.report, "w", encoding="utf-8") as fh:
                fh.write(text_report(snap))
            print(f"report written to {args.report}")
        if args.watch:
            print("Watching traffic. Press Ctrl+C to stop.\n")
            try:
                while True:
                    time.sleep(5)
                    snap = sc.snapshot()
                    talkers = [d for d in snap["devices"]
                               if (d.get("rx_bps") or 0) + (d.get("tx_bps") or 0) > 0]
                    talkers.sort(key=lambda d: -((d.get("rx_bps") or 0) + (d.get("tx_bps") or 0)))
                    stamp = time.strftime("%H:%M:%S")
                    if talkers:
                        for d in talkers[:6]:
                            total = (d.get("rx_bps") or 0) + (d.get("tx_bps") or 0)
                            print(f"  {stamp}  {d['ip']:<16}{(d.get('label') or d.get('hostname') or d.get('type_label'))[:28]:<30}"
                                  f"{total/1e6:8.2f} Mbps  [{d.get('rate_source','')}]")
                    else:
                        print(f"  {stamp}  no traffic counters available yet")
            except KeyboardInterrupt:
                print("\nstopped")
                sc.stop_monitors()
        return 0

    bind_host = "0.0.0.0" if args.lan else args.host

    if not args.serve:
        sc.start_scan()

    # Sign-in is always required (since 1.27), on this PC too. --no-auth is for development only.
    auth_enabled = not args.no_auth
    if args.no_auth:
        print("  WARNING: --no-auth - anyone who can open the dashboard controls Prahari.")
    from netscan import osauth
    windows_login = osauth.available() and (settings.get("auth") or {}).get("windows_login", True)
    if auth_enabled:
        created = auth.ensure_admin()
        if created:
            print()
            print("  " + "=" * 56)
            if windows_login:
                print("   Sign in with your Windows administrator account")
                print("   (the user name and password you use to log in to this PC).")
                print()
                print("   A spare Prahari account was also created:")
            else:
                print("   First run: a dashboard account was created")
            print(f"   user      : {created[0]}")
            print(f"   password  : {created[1]}")
            print("   Change it in Settings, or run: netsentinel.py --set-password YOURPASS")
            print("  " + "=" * 56)
    tls_cfg = settings.get("tls") or {}
    tls_arg = None
    if tls_cfg.get("enabled") or args.tls:
        cert = args.tls_cert or tls_cfg.get("cert") or tlsutil.DEFAULT_CERT
        key = args.tls_key or tls_cfg.get("key") or tlsutil.DEFAULT_KEY
        if not (os.path.exists(cert) and os.path.exists(key)):
            print(f"  no certificate at {cert}")
            print("  create one with: run.bat --make-cert   (or point --tls-cert/--tls-key at your PKI)")
            return 1
        tls_arg = {"cert": cert, "key": key}
        info = tlsutil.describe(cert)
        if info.get("self_signed"):
            print("  WARNING: this certificate is self-signed - browsers will warn until it is trusted.")

    try:
        httpd, url = webui.serve(
            sc, host=bind_host, port=args.port, version=__version__,
            open_browser=not args.no_browser, app_mode=not args.browser,
            auth_enabled=auth_enabled,
            session_hours=int((settings.get("auth") or {}).get("session_hours") or 12),
            tls=tls_arg,
        )
    except Exception as e:
        print(f"  could not start the dashboard: {e}")
        print("  falling back to a one-shot scan")
        do_scan(args, sc)
        return 1

    port = getattr(httpd, "dashboard_port", args.port)
    urls = webui.lan_urls(port)
    print()
    print("  " + "-" * 56)
    print("   DASHBOARD - open this address in Edge or Chrome:")
    print(f"     {urls['local']}")
    if bind_host == "0.0.0.0" and urls["lan"]:
        print(f"     {urls['lan']}   (from other PCs on this network)")
    print("   This window is the Prahari service - keep it open.")
    print("  " + "-" * 56)
    print()
    print(f"  dashboard   : {urls['local']}")
    if bind_host == "0.0.0.0":
        if urls["lan"]:
            print(f"  from laptop : {urls['lan']}   (any device on this network)")
        else:
            print("  from laptop : http://<this-pc-ip>:{}".format(port))
        print("                (if it does not load, run allow_firewall.bat once as Administrator)")
    else:
        print("  from laptop : only this PC can open it. Use dashboard_lan.bat or --lan to share it.")
    print(f"  scanning    : {args.subnet or 'auto-detected subnet'}")
    if not args.no_monitor:
        print(f"  monitoring  : poll every {settings.get('poll_interval_seconds')}s, incidents + alerts")
    sso_cfg = settings.get("oidc") or {}
    if sso_cfg.get("enabled") and getattr(webui.serve, "oidc_error", ""):
        print(f"  SSO         : NOT ACTIVE - {webui.serve.oidc_error}")
    elif sso_cfg.get("enabled"):
        print(f"  SSO         : {sso_cfg.get('issuer')} (roles from '{sso_cfg.get('role_claim')}')")
    print(f"  sign-in     : {('required - Windows administrators of this PC, or Prahari accounts' if windows_login else 'required') if auth_enabled else 'OFF (--no-auth)'}")
    print(f"  transport   : {'HTTPS (TLS on)' if tls_arg else 'HTTP - use --tls for HTTPS'}")
    _tail = tailnet.summary()
    if _tail:
        print(f"  {_tail}")
    print(f"  access      : {__import__('netscan.netguard', fromlist=['describe']).describe(settings.get('access') or {})}")
    if tls_arg:
        watcher = certs_mod.CertWatcher(
            tls_arg["cert"], log=lambda m: print("  " + m),
            restart=lambda: os.execv(sys.executable, [sys.executable] + sys.argv))
        watcher.start()
    if args.no_remote_control:
        print("  remote      : disabled")
    else:
        where = "this PC + other devices" if args.allow_remote_control else "this PC only"
        print(f"  remote      : RDP / VNC / SSH / web / WOL buttons ({where})")
    if args.rescan_every > 0:
        print(f"  auto rescan : every {args.rescan_every}s")
        start_auto_rescan(sc, args.rescan_every)
    upd = updater_mod.Updater(lambda: settings.get("update"), log=lambda m: print("  " + m),
                              on_restart=httpd.shutdown)
    sc.updater = upd
    upd.start()
    _u = settings.get("update") or {}
    if upd.mode == "notify":
        print("  updates     : checked every 6 hours (this copy can't install them itself)")
    elif not _u.get("check", True):
        print("  updates     : off")
    else:
        print(f"  updates     : checked every 6 hours, {'installed automatically' if upd.auto_install else 'installed when you choose'}")
    sc.ensure_branch_reporter()        # report to the portal from the start, not only after the first scan
    _ask_portal_in_console(sc)
    print("  leave this window open. Press Ctrl+C to stop.\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  stopping...")
    finally:
        sc.stop_monitors()
        try:
            httpd.server_close()
        except Exception:
            pass
    if upd.restart_requested:
        print(f"  updated to {upd.latest} - starting the new version ...")
        return upd.handoff()
    return 0


def _ask_portal_in_console(sc):
    """First start in a console: ask for the Prahari portal token, while the dashboard already runs."""
    try:
        interactive = sys.stdin is not None and sys.stdin.isatty()
    except Exception:
        interactive = False
    if not interactive or sites.branch_target()[0] or (settings.get("portal") or {}).get("asked"):
        return

    def ask():
        time.sleep(1.0)
        print()
        print("  " + "=" * 56)
        print("   CONNECT THIS SITE TO THE PRAHARI PORTAL")
        print("   Paste your organisation key from prahari.essensai.workers.dev")
        print("   (shown next to the Download button) to watch this site from anywhere.")
        print("  " + "=" * 56)
        try:
            token = input("   Organisation key (pok_...), or Enter to skip: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not token:
            settings.save({"portal": {"asked": True}})
            print("   skipped - you can connect later on the dashboard's Overview page.\n")
            return
        default = settings.get("site_name") or socket.gethostname()
        try:
            name = input(f"   Name of this site, e.g. Corporate Office [{default}]: ").strip() or default
        except (EOFError, KeyboardInterrupt):
            name = default
        ok, msg = sc.connect_portal(token, name)
        print(("   " if ok else "   NOT CONNECTED: ") + msg + "\n")
        if not ok:
            print("   You can try again on the dashboard's Overview page.\n")

    threading.Thread(target=ask, daemon=True, name="portal-prompt").start()


if __name__ == "__main__":
    sys.exit(main())
