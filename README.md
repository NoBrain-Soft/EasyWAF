# EasyWAF

A WAF reverse proxy for Ubuntu with a visible browser check in front of your site — automatic, or a picture/click/drag puzzle the visitor solves.

```
Visitor ──► EasyWAF server (nginx) ──────────────────────────────► your real site
             │ 1. rate limit per IP
             │ 2. ModSecurity + OWASP Core Rule Set (SQLi, XSS, traversal, …)
             │ 3. browser check: no valid pass cookie → "Checking your browser…" page,
             │    the browser solves a small proof-of-work, gets a signed cookie
             └─ 4. request is forwarded; the proxy stays in front for every request
```

## Install

Copy `install.sh` to the server and run:

```bash
sudo bash install.sh
```

It installs nginx, ModSecurity, the OWASP CRS and certbot, sets up the check service,
and asks whether to add your first site. Works on Ubuntu 22.04 and 24.04.
Re-running it upgrades in place and keeps your sites.

## Add a site

Point the domain's DNS at the EasyWAF server, then:

```bash
sudo easywaf add                     # asks a few questions
# or in one line:
sudo easywaf add shop.example.com http://10.0.0.5:8080 --alias www.shop.example.com --tls --email you@example.com
```

The backend can be `http://` or `https://`, an IP or a hostname. Ideally firewall the
backend so it only accepts connections from the EasyWAF server; otherwise people can bypass it.

## Everyday commands

| Command | What it does |
|---|---|
| `easywaf list` | all sites, HTTPS state, check and WAF mode |
| `easywaf status` | health of nginx, check service, ModSecurity, config |
| `easywaf set <site> key=value …` | change a setting (applied and reloaded immediately) |
| `easywaf edit <site>` | edit all settings in your editor |
| `easywaf tls <site>` | get a Let's Encrypt certificate, turn on HTTPS (auto-renews) |
| `easywaf remove <site>` | stop protecting a site |
| `easywaf logs <site>` / `logs waf` / `logs check` | access log / blocked attacks / check results |
| `easywaf global rate_per_second=30` | global per-IP rate limit |

Every change is tested with `nginx -t` first; if nginx rejects it, the previous config is restored.

## Site settings

| Setting | Default | Meaning |
|---|---|---|
| `backend` | – | real site, e.g. `http://10.0.0.5:8080` |
| `aliases` | – | extra hostnames, comma separated |
| `challenge` | `on` | show the browser check |
| `challenge_type` | `auto` | `auto`: no clicks, about a second. `select`: pick every picture with a given symbol. `click`: click a named symbol, or the one that's upside down. `drag`: slide a puzzle piece into its gap. `manual`: a random one of select/click/drag each time |
| `difficulty` | `16` | proof-of-work bits. 12 ≈ instant, 16 ≈ 1 s, 18 ≈ 3 s; each +1 doubles the work |
| `ttl_hours` | `24` | how long a passed check is valid. `0` = until the browser is closed (session cookie, nothing stored on disk; capped at 12 h) |
| `bind_ip` | `on` | pass is tied to the visitor's IP (turn off if users' IPs change a lot, e.g. mobile) |
| `block_automation` | `on` | reject browsers that report being automated (`navigator.webdriver`) |
| `skip_paths` | – | prefixes without the check, e.g. `/api/,/webhooks/` (WAF still applies) |
| `allow_ips` | – | IPs/CIDRs that never see the check, e.g. your office or monitoring |
| `waf` | `on` | `on` blocks attacks, `detect` only logs them, `off` disables ModSecurity |
| `preserve_host` | `on` | send the visitor's Host header to the backend |
| `max_body` | `50m` | max upload size |
| `burst` | `100` | requests allowed above the rate limit before 429 |

Examples:

```bash
sudo easywaf set shop.example.com skip_paths=/api/,/hooks/ allow_ips=203.0.113.10
sudo easywaf set shop.example.com waf=detect     # first week: watch `easywaf logs waf` for false positives
sudo easywaf set shop.example.com difficulty=18  # under attack: make the check harder
sudo easywaf set shop.example.com challenge_type=manual ttl_hours=0   # visitors solve a puzzle every browser session
```

## Notes

- **APIs, apps and webhooks** can't run the JavaScript check — put their paths in `skip_paths`.
- **Manual challenges** need sight (the drag puzzle also works with arrow keys and Enter). For sites where that matters, keep `auto`, or use manual only while under attack.
- Pending manual challenges live in the check service's memory; restarting it just shows visitors a fresh challenge.
- **False positives:** add exclusions to `/etc/easywaf/modsec/custom-after.conf`
  (e.g. `SecRuleRemoveById 942100`), then `sudo easywaf rebuild`.
- **Custom page:** copy the HTML from `CHALLENGE_HTML` in `/opt/easywaf/easywaf.py` to
  `/etc/easywaf/challenge.html` and edit it; keep the `{{…}}` placeholders and the form.
- **Behind another load balancer/CDN:** the check binds to the IP nginx sees. Configure
  nginx `real_ip` for your LB, or set `bind_ip=off`.
- The check stops simple bots, scrapers and floods of scripted requests. A determined attacker
  running a real browser can still pass it, so keep the backend firewalled and patched.
- Uninstall: `sudo bash install.sh --uninstall`.
