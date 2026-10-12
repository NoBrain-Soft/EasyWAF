#!/usr/bin/env bash
# =============================================================================
#  EasyWAF installer - WAF reverse proxy with a visible browser check
#  Tested on Ubuntu 22.04 / 24.04.
#
#    sudo bash install.sh                 install (asks to add your first site)
#    sudo bash install.sh --no-prompt     install without questions
#    sudo bash install.sh --uninstall     remove EasyWAF (keeps nginx installed)
# =============================================================================
set -euo pipefail

PREFIX=/opt/easywaf
ETC=/etc/easywaf
PROMPT=1
ACTION=install
for arg in "$@"; do
  case "$arg" in
    --no-prompt|-y) PROMPT=0 ;;
    --uninstall)    ACTION=uninstall ;;
    -h|--help)      sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg"; exit 1 ;;
  esac
done

c_ok()   { printf '\033[32m✓\033[0m %s\n' "$*"; }
c_info() { printf '\033[36m•\033[0m %s\n' "$*"; }
c_warn() { printf '\033[33m!\033[0m %s\n' "$*"; }
c_err()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || c_err "please run as root: sudo bash $0"
command -v apt-get >/dev/null || c_err "this installer needs Ubuntu/Debian (apt-get)"

# -----------------------------------------------------------------------------
if [ "$ACTION" = uninstall ]; then
  c_info "removing EasyWAF"
  systemctl disable --now easywaf 2>/dev/null || true
  rm -f /etc/systemd/system/easywaf.service /usr/local/bin/easywaf \
        /etc/nginx/conf.d/easywaf.conf /etc/letsencrypt/renewal-hooks/deploy/easywaf-reload.sh
  systemctl daemon-reload
  if [ -f /etc/nginx/sites-available/default ] && [ ! -e /etc/nginx/sites-enabled/default ]; then
    ln -s /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default
  fi
  nginx -t >/dev/null 2>&1 && systemctl reload nginx || true
  rm -rf "$PREFIX"
  c_ok "EasyWAF removed. Site settings were kept in $ETC (delete with: rm -rf $ETC)"
  exit 0
fi

# -----------------------------------------------------------------------------
. /etc/os-release 2>/dev/null || true
c_info "installing EasyWAF on ${PRETTY_NAME:-unknown OS}"

export DEBIAN_FRONTEND=noninteractive
c_info "installing packages (nginx, python3, certbot)…"
apt-get update -q >/dev/null
apt-get install -y -q nginx python3 certbot ca-certificates >/dev/null
c_ok "base packages installed"

MODSEC=false
if apt-get install -y -q libnginx-mod-http-modsecurity modsecurity-crs >/dev/null 2>&1; then
  if ls /etc/nginx/modules-enabled/ 2>/dev/null | grep -qi modsecurity; then
    MODSEC=true
    c_ok "ModSecurity + OWASP Core Rule Set installed"
  fi
fi
$MODSEC || c_warn "ModSecurity not available on this system - continuing with browser check + rate limiting only"

CRS_SETUP=/etc/modsecurity/crs/crs-setup.conf
CRS_RULES=/usr/share/modsecurity-crs/rules
if $MODSEC; then
  [ -f "$CRS_SETUP" ] || CRS_SETUP=$(find /etc/modsecurity /usr/share/modsecurity-crs -name 'crs-setup.conf*' 2>/dev/null | head -1)
  [ -d "$CRS_RULES" ] || CRS_RULES=$(dirname "$(find /usr/share -name 'REQUEST-901-INITIALIZATION.conf' 2>/dev/null | head -1)")
  if [ -z "$CRS_SETUP" ] || [ ! -f "$CRS_RULES/REQUEST-901-INITIALIZATION.conf" ]; then
    c_warn "could not locate the OWASP CRS files - ModSecurity disabled"
    MODSEC=false
  fi
fi

IPV6=true
[ -s /proc/net/if_inet6 ] || IPV6=false

# --- user, folders -----------------------------------------------------------
id easywaf >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin easywaf
install -d -m 755 "$PREFIX" "$ETC" "$ETC/nginx" "$ETC/modsec" /var/lib/easywaf /var/lib/easywaf/acme
install -d -m 750 "$ETC/sites"
install -d -m 750 -o www-data -g adm /var/log/easywaf

# --- program -----------------------------------------------------------------
cat > "$PREFIX/easywaf.py" <<'EASYWAF_PY_EOF'
#!/usr/bin/env python3
"""
EasyWAF - a small WAF reverse proxy for Ubuntu.

  nginx  +  ModSecurity / OWASP Core Rule Set  +  a visible browser check

This one file is both:
  * the challenge service (`easywaf serve`, run by systemd), which nginx asks
    via auth_request whether a visitor has passed the browser check, and
  * the management CLI (`easywaf add`, `easywaf list`, ...), which writes the
    nginx configuration for every protected site.

Only the Python standard library is used.
"""

import argparse
import base64
import colorsys
import hashlib
import hmac
import html
import ipaddress
import json
import math
import os
import random
import re
import secrets
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

VERSION = "1.1.0"

ETC = os.environ.get("EASYWAF_ETC", "/etc/easywaf")
SITES_DIR = os.path.join(ETC, "sites")
NGINX_SITES_DIR = os.path.join(ETC, "nginx")
GLOBAL_CONF = os.path.join(ETC, "config.json")
SECRET_FILE = os.path.join(ETC, "secret.key")
CUSTOM_PAGE = os.path.join(ETC, "challenge.html")
NGINX_GLOBAL = "/etc/nginx/conf.d/easywaf.conf"
ACME_ROOT = "/var/lib/easywaf/acme"
LOG_DIR = "/var/log/easywaf"
LE_LIVE = "/etc/letsencrypt/live"

COOKIE_NAME = "__easywaf"
CHALLENGE_MAX_AGE = 300          # seconds a challenge token stays valid
MAX_DIFFICULTY = 26

DEFAULT_GLOBAL = {
    "listen": "127.0.0.1:8099",  # challenge service (never expose publicly)
    "rate_per_second": 20,       # per-IP request rate before 429
    "modsecurity": False,        # set by the installer if the module is present
    "crs_setup": "/etc/modsecurity/crs/crs-setup.conf",
    "crs_rules": "/usr/share/modsecurity-crs/rules",
    "ipv6": True,
}

DEFAULT_SITE = {
    "domain": "",
    "aliases": [],               # extra hostnames, e.g. www.example.com
    "backend": "",               # http(s)://host:port of the real site
    "preserve_host": True,       # send the visitor's Host header to the backend
    "tls": False,                # HTTPS via Let's Encrypt (easywaf tls <domain>)
    "challenge": True,           # show the browser check
    "challenge_type": "auto",    # auto (no clicks) | select | click | drag | manual (random of the three)
    "difficulty": 16,            # proof-of-work bits; 16 ~ 1s, each +1 doubles
    "ttl_hours": 24,             # how long a passed check stays valid; 0 = until the browser closes
    "bind_ip": True,             # pass is tied to the visitor's IP address
    "block_automation": True,    # reject browsers that report navigator.webdriver
    "waf": "on",                 # on | detect | off   (ModSecurity mode)
    "skip_paths": [],            # path prefixes without browser check, e.g. /api/
    "allow_ips": [],             # IPs/CIDRs that never see the check
    "max_body": "50m",
    "burst": 100,                # extra requests allowed above the rate limit
}

HOST_RE = re.compile(r"^(?=.{1,253}$)(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

def die(msg, code=1):
    print(f"\033[31merror:\033[0m {msg}", file=sys.stderr)
    sys.exit(code)


def ok(msg):
    print(f"\033[32m✓\033[0m {msg}")


def info(msg):
    print(f"\033[36m•\033[0m {msg}")


def warn(msg):
    print(f"\033[33m!\033[0m {msg}")


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def load_json(path, default):
    try:
        with open(path) as f:
            data = json.load(f)
    except FileNotFoundError:
        return dict(default)
    merged = dict(default)
    merged.update(data)
    return merged


def write_file(path, content, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path))
    with os.fdopen(fd, "w") as f:
        f.write(content)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def load_secret() -> bytes:
    with open(SECRET_FILE, "rb") as f:
        key = f.read().strip()
    if len(key) < 32:
        raise RuntimeError(f"{SECRET_FILE} is too short")
    return key


def leading_zero_bits(digest: bytes) -> int:
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        bits += 8 - byte.bit_length()
        break
    return bits


# --------------------------------------------------------------------------
# picture challenge: tiles are drawn as PNGs (pure Python, no libraries), so
# the answer is not readable from the page source - a bot has to "see" them.
# --------------------------------------------------------------------------


TILE = 96

# name shown to the visitor -> drawing function (shapes in a 100x100 space)
def _circle(cx, cy, r, n=30):
    return [(cx + r * math.cos(2 * math.pi * i / n), cy + r * math.sin(2 * math.pi * i / n)) for i in range(n)]


def _ellipse(cx, cy, rx, ry, n=30):
    return [(cx + rx * math.cos(2 * math.pi * i / n), cy + ry * math.sin(2 * math.pi * i / n)) for i in range(n)]


def _rect(x0, y0, x1, y1):
    return [(x0, y0), (x1, y0), (x1, y1), (x0, y1)]


def _arc(cx, cy, r, a0, a1, n=20):
    return [(cx + r * math.cos(a0 + (a1 - a0) * i / n), cy + r * math.sin(a0 + (a1 - a0) * i / n)) for i in range(n + 1)]


def _star(cx, cy, ro, ri, k=5):
    pts = []
    for i in range(2 * k):
        r = ro if i % 2 == 0 else ri
        a = -math.pi / 2 + math.pi * i / k
        pts.append((cx + r * math.cos(a), cy + r * math.sin(a)))
    return pts


SHAPES = {
    "fish": lambda: [(_ellipse(44, 50, 27, 15), "fg"), ([(66, 50), (88, 34), (84, 50), (88, 66)], "fg"),
                     (_circle(30, 46, 3.2), "bg")],
    "house": lambda: [(_rect(28, 48, 72, 80), "fg"), ([(20, 51), (50, 22), (80, 51)], "fg2"),
                      (_rect(45, 61, 56, 80), "bg")],
    "tree": lambda: [(_rect(45, 60, 55, 86), "fg2"), (_circle(50, 40, 23), "fg")],
    "star": lambda: [(_star(50, 52, 34, 14), "fg")],
    "car": lambda: [([(12, 66), (88, 66), (88, 52), (70, 49), (60, 35), (34, 35), (25, 49), (12, 52)], "fg"),
                    (_rect(37, 39, 57, 49), "bg"), (_circle(31, 67, 9), "fg2"), (_circle(69, 67, 9), "fg2")],
    "heart": lambda: [(_circle(37, 42, 15), "fg"), (_circle(63, 42, 15), "fg"), ([(23, 48), (77, 48), (50, 80)], "fg")],
    "umbrella": lambda: [(_arc(50, 50, 33, math.pi, 2 * math.pi) + [(83, 50)], "fg"),
                         (_rect(48, 48, 53, 80), "fg2"), (_rect(38, 76, 53, 81), "fg2")],
    "key": lambda: [(_circle(28, 50, 15), "fg"), (_circle(28, 50, 6), "bg"), (_rect(40, 46, 86, 54), "fg"),
                    (_rect(72, 54, 78, 64), "fg"), (_rect(80, 54, 86, 61), "fg")],
    "sun": lambda: [(_circle(50, 50, 15), "fg")] + [
        ([(50 + 20 * math.cos(a - 0.22), 50 + 20 * math.sin(a - 0.22)),
          (50 + 36 * math.cos(a), 50 + 36 * math.sin(a)),
          (50 + 20 * math.cos(a + 0.22), 50 + 20 * math.sin(a + 0.22))], "fg")
        for a in [i * math.pi / 4 for i in range(8)]],
    "moon": lambda: [(_circle(48, 52, 28), "fg"), (_circle(61, 42, 24), "bg")],
    "cup": lambda: [(_circle(68, 52, 12), "fg2"), (_circle(68, 52, 6), "bg"), (_rect(28, 34, 66, 78), "fg"),
                    (_rect(22, 78, 74, 83), "fg2")],
    "bell": lambda: [(_arc(50, 44, 18, math.pi, 2 * math.pi) + [(70, 70), (30, 70)], "fg"),
                     (_rect(24, 68, 76, 74), "fg2"), (_circle(50, 77, 5), "fg2")],
}

LABELS = {"fish": "a fish", "house": "a house", "tree": "a tree", "star": "a star", "car": "a car",
          "heart": "a heart", "umbrella": "an umbrella", "key": "a key", "sun": "a sun", "moon": "a moon",
          "cup": "a cup", "bell": "a bell"}


class _Canvas:
    def __init__(self, w, h, bg):
        self.w, self.h = w, h
        self.px = bytearray(bytes(bg) * (w * h))

    def poly(self, pts, col):
        n = len(pts)
        ys = [p[1] for p in pts]
        y0, y1 = max(0, int(min(ys))), min(self.h - 1, int(max(ys)) + 1)
        fill = bytes(col)
        for y in range(y0, y1 + 1):
            yc = y + 0.5
            xs = []
            for i in range(n):
                xa, ya = pts[i]
                xb, yb = pts[(i + 1) % n]
                if (ya <= yc < yb) or (yb <= yc < ya):
                    xs.append(xa + (yc - ya) * (xb - xa) / (yb - ya))
            xs.sort()
            row = y * self.w * 3
            for k in range(0, len(xs) - 1, 2):
                a = max(0, int(xs[k] + 0.5))
                b = min(self.w, int(xs[k + 1] + 0.5))
                if b > a:
                    self.px[row + a * 3:row + b * 3] = fill * (b - a)

    def png(self):
        raw = b"".join(b"\x00" + bytes(self.px[y * self.w * 3:(y + 1) * self.w * 3]) for y in range(self.h))

        def chunk(tag, data):
            return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", self.w, self.h, 8, 2, 0, 0, 0))
                + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def _rgb(h, s, l):
    return tuple(int(c * 255) for c in colorsys.hls_to_rgb(h % 1.0, l, s))


def _line(x0, y0, x1, y1, w):
    dx, dy = x1 - x0, y1 - y0
    d = math.hypot(dx, dy) or 1
    nx, ny = -dy / d * w / 2, dx / d * w / 2
    return [(x0 + nx, y0 + ny), (x1 + nx, y1 + ny), (x1 - nx, y1 - ny), (x0 - nx, y0 - ny)]


def _palette(rng, dark=None):
    dark = rng.random() < 0.3 if dark is None else dark
    bh = rng.random()
    bg = _rgb(bh, rng.uniform(0.15, 0.45), rng.uniform(0.14, 0.22) if dark else rng.uniform(0.80, 0.91))
    return dark, bh, bg


def _fg(rng, bh, dark):
    fh = bh + rng.uniform(0.25, 0.75)
    fl = rng.uniform(0.62, 0.75) if dark else rng.uniform(0.28, 0.45)
    fg = _rgb(fh, rng.uniform(0.5, 0.85), fl)
    fg2 = _rgb(fh + rng.uniform(-0.08, 0.08), rng.uniform(0.4, 0.8), fl * 0.75 if not dark else min(0.85, fl * 1.15))
    return fg, fg2


def _clutter(cv, rng, bh, dark, n):
    for _ in range(n):
        cx, cy, r = rng.uniform(0, cv.w), rng.uniform(0, cv.h), rng.uniform(8, 20) * cv.h / 100
        blob = [(cx + r * rng.uniform(0.6, 1.2) * math.cos(a), cy + r * rng.uniform(0.6, 1.2) * math.sin(a))
                for a in [2 * math.pi * i / 7 for i in range(7)]]
        cv.poly(blob, _rgb(bh + rng.uniform(-0.1, 0.1), rng.uniform(0.15, 0.4),
                           rng.uniform(0.2, 0.28) if dark else rng.uniform(0.72, 0.84)))


def _noise(cv, rng, lines, dots):
    for _ in range(lines):
        col = _rgb(rng.random(), rng.uniform(0.3, 0.7), rng.uniform(0.35, 0.7))
        cv.poly(_line(rng.uniform(-10, cv.w + 10), rng.uniform(-10, cv.h + 10),
                      rng.uniform(-10, cv.w + 10), rng.uniform(-10, cv.h + 10), rng.uniform(1.0, 2.0)), col)
    for _ in range(dots):
        col = _rgb(rng.random(), rng.uniform(0.3, 0.8), rng.uniform(0.3, 0.75))
        cv.poly(_circle(rng.uniform(0, cv.w), rng.uniform(0, cv.h), rng.uniform(0.8, 2.0), 6), col)


def draw_shape(cv, shape, cx, cy, size, deg, flip, fg, fg2, bg):
    """Draw a symbol centred on (cx, cy), `size` pixels across, rotated `deg` degrees."""
    ang = math.radians(deg)
    sc = size / 100
    ca, sa = math.cos(ang), math.sin(ang)

    def tf(p):
        x, y = (p[0] - 50) * flip, p[1] - 50
        return (cx + (x * ca - y * sa) * sc, cy + (x * sa + y * ca) * sc)

    colors = {"fg": fg, "fg2": fg2, "bg": bg}
    for pts, role in SHAPES[shape]():
        cv.poly([tf(p) for p in pts], colors[role])


def draw_tile(shape, rng):
    dark, bh, bg = _palette(rng)
    fg, fg2 = _fg(rng, bh, dark)
    cv = _Canvas(TILE, TILE, bg)
    _clutter(cv, rng, bh, dark, rng.randint(2, 4))
    draw_shape(cv, shape, TILE / 2 + rng.uniform(-7, 7), TILE / 2 + rng.uniform(-7, 7),
               TILE * rng.uniform(0.78, 1.0), rng.uniform(-28, 28), -1 if rng.random() < 0.5 else 1, fg, fg2, bg)
    _noise(cv, rng, rng.randint(5, 9), rng.randint(25, 45))
    return cv.png()


def make_picture_set(n=9):
    """Returns (target_name, label, [png bytes], answer_mask_string)."""
    rng = random.SystemRandom()
    names = list(SHAPES)
    target = rng.choice(names)
    count = rng.randint(2, 4)
    others = [x for x in names if x != target]
    tiles = [target] * count + [rng.choice(others) for _ in range(n - count)]
    rng.shuffle(tiles)
    mask = "".join("1" if t == target else "0" for t in tiles)
    return target, LABELS[target], [draw_tile(t, rng) for t in tiles], mask


# shapes that look clearly wrong upside down
UPRIGHT = ["house", "tree", "umbrella", "bell", "cup", "car", "heart"]
SCENE_W, SCENE_H = 288, 160


def _spread(rng, n, w, h, margin, gap):
    """n points inside w x h, at least `gap` apart."""
    for _ in range(200):
        pts = []
        for _ in range(n * 40):
            x, y = rng.uniform(margin, w - margin), rng.uniform(margin, h - margin)
            if all(math.hypot(x - a, y - b) >= gap for a, b in pts):
                pts.append((x, y))
                if len(pts) == n:
                    return pts
    return pts


def make_click_scene():
    """One picture with several symbols; the visitor clicks the right one.
    Returns (prompt_html, png, (target_x, target_y))."""
    rng = random.SystemRandom()
    dark, bh, bg = _palette(rng)
    cv = _Canvas(SCENE_W, SCENE_H, bg)
    _clutter(cv, rng, bh, dark, rng.randint(5, 8))
    n = rng.randint(5, 7)
    spots = _spread(rng, n, SCENE_W, SCENE_H, 30, 62)
    n = len(spots)
    if rng.random() < 0.5:
        shapes = rng.sample(list(SHAPES), n)
        t = rng.randrange(n)
        noun = LABELS[shapes[t]].split(" ", 1)[1]
        prompt = f"Click the <strong>{html.escape(noun)}</strong>."
        rots = [rng.uniform(-25, 25) for _ in range(n)]
    else:
        shape = rng.choice(UPRIGHT)
        shapes = [shape] * n
        t = rng.randrange(n)
        noun = LABELS[shape].split(" ", 1)[1]
        prompt = f"Click the <strong>{html.escape(noun)} that is upside down</strong>."
        rots = [rng.uniform(-18, 18) for _ in range(n)]
        rots[t] = 180 + rng.uniform(-18, 18)
    for i, (x, y) in enumerate(spots):
        fg, fg2 = _fg(rng, bh, dark)
        draw_shape(cv, shapes[i], x, y, rng.uniform(44, 54), rots[i], -1 if rng.random() < 0.5 else 1, fg, fg2, bg)
    _noise(cv, rng, rng.randint(9, 14), rng.randint(60, 90))
    return prompt, cv.png(), (int(spots[t][0]), int(spots[t][1]))


PIECE = 44
PUZZLE_W, PUZZLE_H = 288, 144


def make_puzzle():
    """A picture with a square gap and the matching piece; the visitor slides
    the piece into the gap. Returns (background_png, piece_png, piece_top, gap_x)."""
    rng = random.SystemRandom()
    dark, bh, bg = _palette(rng)
    cv = _Canvas(PUZZLE_W, PUZZLE_H, bg)
    _clutter(cv, rng, bh, dark, rng.randint(7, 11))
    for x, y in _spread(rng, 5, PUZZLE_W, PUZZLE_H, 24, 54):
        fg, fg2 = _fg(rng, bh, dark)
        draw_shape(cv, rng.choice(list(SHAPES)), x, y, rng.uniform(40, 56), rng.uniform(-30, 30), 1, fg, fg2, bg)
    _noise(cv, rng, rng.randint(8, 12), rng.randint(60, 90))
    gx = rng.randint(PIECE + 40, PUZZLE_W - PIECE - 6)
    gy = rng.randint(10, PUZZLE_H - PIECE - 10)

    piece = _Canvas(PIECE, PIECE, (0, 0, 0))
    edge = (250, 250, 245)
    for yy in range(PIECE):
        for xx in range(PIECE):
            i = ((gy + yy) * PUZZLE_W + gx + xx) * 3
            j = (yy * PIECE + xx) * 3
            if xx < 2 or yy < 2 or xx >= PIECE - 2 or yy >= PIECE - 2:
                piece.px[j:j + 3] = bytes(edge)
            else:
                piece.px[j:j + 3] = cv.px[i:i + 3]
            # darken the gap in the background, with a light outline
            if xx < 1 or yy < 1 or xx >= PIECE - 1 or yy >= PIECE - 1:
                cv.px[i:i + 3] = bytes((235, 235, 230))
            else:
                cv.px[i:i + 3] = bytes(int(v * 0.42) for v in cv.px[i:i + 3])
    return cv.png(), piece.png(), gy, gx


# --------------------------------------------------------------------------
# challenge service
# --------------------------------------------------------------------------

SESSION_PASS_MAX = 12 * 3600   # ttl_hours=0: browser-session pass, but never longer than this
MANUAL_KINDS = ("select", "click", "drag")
CHALLENGE_TYPES = ("auto", "manual") + MANUAL_KINDS
CLICK_TOLERANCE = 26           # pixels (in the 288x160 picture) from the symbol's centre
DRAG_TOLERANCE = 6             # pixels (in the 288x144 picture) from the gap
WRONG_NOTICE = {
    "select": "Those weren't the right pictures. Here's a new set to try.",
    "click": "That wasn't the right symbol. Here's a new picture to try.",
    "drag": "The piece wasn't in the gap. Here's a new puzzle to try.",
}


class Challenge:
    """Tokens are HMAC-signed with the local secret. Used tokens are remembered
    in memory until they expire, so each one can be submitted only once."""

    def __init__(self, secret: bytes):
        self.secret = secret
        self.used = {}
        self.pending = {}   # manual challenges: token id -> (expires, kind, answer)
        self.lock = threading.Lock()

    def _sig(self, msg: str) -> str:
        return hmac.new(self.secret, msg.encode(), hashlib.sha256).hexdigest()[:40]

    @staticmethod
    def ua_hash(ua: str) -> str:
        return hashlib.sha256(ua.encode("utf-8", "replace")).hexdigest()[:16]

    def _burn(self, tid):
        """Mark a token as used. Returns False if it was used before."""
        now = time.time()
        with self.lock:
            if len(self.used) > 50000 or (self.used and secrets.randbelow(200) == 0):
                self.used = {k: v for k, v in self.used.items() if v > now}
                self.pending = {k: v for k, v in self.pending.items() if v[0] > now}
            if len(self.pending) > 50000:
                self.pending.clear()
            if tid in self.used:
                return False
            self.used[tid] = now + CHALLENGE_MAX_AGE + 5
            return True

    # pass cookie --------------------------------------------------------
    def make_pass(self, site, ip, ua, ttl, bind_ip):
        exp = int(time.time()) + (ttl if ttl > 0 else SESSION_PASS_MAX)
        ipv = ip if bind_ip else "-"
        sig = self._sig(f"pass|{site}|{exp}|{ipv}|{self.ua_hash(ua)}")
        return f"{exp}.{sig}"

    def check_pass(self, value, site, ip, ua, bind_ip):
        try:
            exp_s, sig = value.split(".", 1)
            exp = int(exp_s)
        except ValueError:
            return False
        if exp < time.time():
            return False
        ipv = ip if bind_ip else "-"
        good = self._sig(f"pass|{site}|{exp}|{ipv}|{self.ua_hash(ua)}")
        return hmac.compare_digest(good, sig)

    # challenge token ----------------------------------------------------
    def make_token(self, site, ip, ua, difficulty, kind, answer=None):
        tid = secrets.token_hex(8)
        if kind != "auto":
            with self.lock:
                self.pending[tid] = (time.time() + CHALLENGE_MAX_AGE + 5, kind, answer)
        payload = f"{site}|{difficulty}|{int(time.time())}|{ip}|{self.ua_hash(ua)}|{tid}|{kind}|-"
        return f"{b64u(payload.encode())}.{self._sig('tok|' + payload)}"

    def check_solution(self, token, nonce, answer, moves, site, ip, ua):
        """Returns (ok, reason, kind)."""
        try:
            enc, sig = token.split(".", 1)
            payload = base64.urlsafe_b64decode(enc + "=" * (-len(enc) % 4)).decode()
            t_site, t_diff, t_ts, t_ip, t_ua, tid, kind, ans = payload.split("|")
            difficulty, ts = int(t_diff), int(t_ts)
        except Exception:
            return False, "malformed token", "auto"
        if not hmac.compare_digest(self._sig("tok|" + payload), sig):
            return False, "bad signature", kind
        if t_site != site or t_ip != ip or t_ua != self.ua_hash(ua):
            return False, "token bound to another visitor", kind
        if time.time() - ts > CHALLENGE_MAX_AGE:
            return False, "token expired", kind
        if not re.fullmatch(r"\d{1,12}", nonce or ""):
            return False, "bad nonce", kind
        if leading_zero_bits(hashlib.sha256(f"{token}:{nonce}".encode()).digest()) < difficulty:
            return False, "insufficient work", kind
        if not self._burn(tid):
            return False, "token already used", kind
        if kind == "auto":
            return True, "ok", kind
        with self.lock:
            entry = self.pending.pop(tid, None)
        if not entry or entry[0] < time.time():
            return False, "token expired", kind   # also after a service restart
        want = entry[2]
        answer = answer or ""
        if kind == "select":
            good = re.fullmatch(r"[01]{9}", answer) is not None and hmac.compare_digest(answer, want)
        elif kind == "click":
            m = re.fullmatch(r"(\d{1,4}),(\d{1,4})", answer)
            good = bool(m) and math.hypot(int(m[1]) - want[0], int(m[2]) - want[1]) <= CLICK_TOLERANCE
        elif kind == "drag":
            good = (re.fullmatch(r"\d{1,4}", answer) is not None and abs(int(answer) - want) <= DRAG_TOLERANCE
                    and moves >= 3)
        else:
            good = False
        return (True, "ok", kind) if good else (False, "wrong answer", kind)


SECOND_LEVEL = {"co", "com", "net", "org", "gv", "or", "ac", "gov", "edu", "ltd", "plc", "ne", "go"}


def host_html(host):
    """Show the registrable domain stronger than the subdomain, so visitors can
    see at a glance which site is really asking (shop.<b>example.com</b>)."""
    host = (host or "").split(":")[0].lower()
    labels = host.split(".")
    keep = 3 if len(labels) >= 3 and labels[-2] in SECOND_LEVEL and len(labels[-1]) == 2 else 2
    sub, base = ".".join(labels[:-keep]), ".".join(labels[-keep:])
    out = f'<span class="sub">{html.escape(sub)}.</span>' if sub else ""
    return out + f'<span class="base">{html.escape(base)}</span>'


def challenge_page(mode, host, ray, token="", difficulty=0, return_to="/", prompt="", block="", notice=""):
    try:
        with open(CUSTOM_PAGE) as f:
            tpl = f.read()
    except OSError:
        tpl = CHALLENGE_HTML
    values = {
        "{{MODE}}": mode,
        "{{HOST}}": html.escape(host),
        "{{HOST_HTML}}": host_html(host),
        "{{TOKEN}}": html.escape(token),
        "{{DIFFICULTY}}": str(int(difficulty)),
        "{{RETURN}}": html.escape(return_to),
        "{{RAY}}": html.escape(ray),
        "{{PROMPT_HTML}}": prompt,
        "{{CHALLENGE}}": block,
        "{{NOTICE}}": html.escape(notice),
    }
    for k, v in values.items():
        tpl = tpl.replace(k, v)
    return tpl


def _data_uri(png):
    return "data:image/png;base64," + base64.b64encode(png).decode()


def build_manual(kind):
    """Returns (prompt_html, challenge_html, expected_answer) for one manual challenge."""
    if kind == "select":
        _, label, tiles, mask = make_picture_set()
        block = '<div class="grid" role="group" aria-labelledby="ask">' + "".join(
            f'<button type="button" class="tile" aria-pressed="false" aria-label="Picture {i + 1}">'
            f'<img src="{_data_uri(p)}" alt="" width="{TILE}" height="{TILE}">'
            f'<span class="mark" aria-hidden="true"></span></button>' for i, p in enumerate(tiles)) + "</div>"
        return f"Select every picture with <strong>{html.escape(label)}</strong>.", block, mask
    if kind == "click":
        prompt, png, target = make_click_scene()
        block = (f'<div class="scene" id="scene"><img src="{_data_uri(png)}" alt="" width="{SCENE_W}" '
                 f'height="{SCENE_H}" draggable="false"><span class="pick-mark" hidden></span></div>')
        return prompt, block, target
    bg, piece, gy, gx = make_puzzle()
    block = (f'<div class="puzzle" id="puzzle" style="--gy:{gy}">'
             f'<img src="{_data_uri(bg)}" alt="" width="{PUZZLE_W}" height="{PUZZLE_H}" draggable="false">'
             f'<img class="piece" id="piece" src="{_data_uri(piece)}" alt="" draggable="false"></div>'
             f'<div class="track" id="track"><button type="button" class="knob" id="knob" '
             f'aria-label="Move the piece. Use the arrow keys." role="slider" aria-valuemin="0" '
             f'aria-valuemax="{PUZZLE_W - PIECE}" aria-valuenow="0"><span></span></button></div>')
    return "Drag the slider until the piece fits into the gap.", block, gx


def safe_return(uri):
    if not uri or not uri.startswith("/") or uri.startswith("//") or "\\" in uri:
        return "/"
    if uri.startswith("/__waf/"):
        return "/"
    return uri[:2048]


class Handler(BaseHTTPRequestHandler):
    server_version = "easywaf"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    challenge: Challenge = None  # set at startup

    def log_message(self, fmt, *args):  # quiet default access log
        pass

    # settings that nginx passes per request -------------------------------
    def ctx(self):
        h = self.headers
        try:
            difficulty = max(0, min(MAX_DIFFICULTY, int(h.get("X-WAF-Difficulty", "16"))))
        except ValueError:
            difficulty = 16
        try:
            ttl = max(0, int(h.get("X-WAF-TTL", "86400")))
        except ValueError:
            ttl = 86400
        return {
            "site": h.get("X-WAF-Site", "default"),
            "host": h.get("X-WAF-Host", "") or h.get("Host", ""),
            "ip": h.get("X-Real-IP", self.client_address[0]),
            "ua": h.get("User-Agent", ""),
            "difficulty": difficulty,
            "ttl": ttl,
            "kind": h.get("X-WAF-Type") if h.get("X-WAF-Type") in CHALLENGE_TYPES else "auto",
            "bind_ip": h.get("X-WAF-Bind-IP", "1") == "1",
            "secure": h.get("X-WAF-Scheme", "http") == "https",
            "block_automation": h.get("X-WAF-Block-Automation", "1") == "1",
        }

    def cookie(self, name):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return None

    def send(self, status, body=b"", ctype="text/html; charset=utf-8", headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("X-Robots-Tag", "noindex, nofollow")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("X-Frame-Options", "DENY")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def drain_body(self, limit=8192):
        length = int(self.headers.get("Content-Length") or 0)
        if length > limit:
            return None
        return self.rfile.read(length) if length else b""

    # routes -----------------------------------------------------------------
    def route(self):
        path = urlsplit(self.path).path
        if path == "/auth":
            return self.do_auth()
        if path == "/challenge":
            return self.do_challenge()
        if path == "/verify" and self.command == "POST":
            return self.do_verify()
        if path == "/health":
            return self.send(200, "ok\n", "text/plain")
        return self.send(404, "not found\n", "text/plain")

    def do_auth(self):
        c = self.ctx()
        value = self.cookie(COOKIE_NAME)
        if value and self.challenge.check_pass(value, c["site"], c["ip"], c["ua"], c["bind_ip"]):
            return self.send(204)
        return self.send(401)

    def issue(self, c, ret, notice=""):
        ray = secrets.token_hex(8)
        kind = c["kind"]
        if kind == "manual":
            kind = secrets.choice(MANUAL_KINDS)
        if kind in MANUAL_KINDS:
            prompt, block, answer = build_manual(kind)
            token = self.challenge.make_token(c["site"], c["ip"], c["ua"], c["difficulty"], kind, answer)
            page = challenge_page(kind, c["host"] or c["site"], ray, token, c["difficulty"], ret,
                                  prompt=prompt, block=block, notice=notice)
        else:
            token = self.challenge.make_token(c["site"], c["ip"], c["ua"], c["difficulty"], "auto")
            page = challenge_page("auto", c["host"] or c["site"], ray, token, c["difficulty"], ret, notice=notice)
        print(f"challenge site={c['site']} type={kind if c['kind'] == 'manual' else c['kind']} ip={c['ip']} ray={ray}",
              flush=True)
        self.send(403, page, headers={"X-WAF-Ray": ray})

    def do_challenge(self):
        c = self.ctx()
        self.drain_body(limit=10**9)  # discard POST bodies of challenged requests
        self.issue(c, safe_return(self.headers.get("X-Original-URI", "/")))

    def do_verify(self):
        c = self.ctx()
        raw = self.drain_body()
        if raw is None:
            return self.send(413, "too large\n", "text/plain")
        form = {k: v[0] for k, v in parse_qs(raw.decode("utf-8", "replace")).items()}
        ret = safe_return(form.get("r", "/"))
        if c["block_automation"] and form.get("wd") == "1":
            good, why, kind = False, "automation detected", "auto"
        else:
            try:
                moves = int(form.get("e", "0")[:6])
            except ValueError:
                moves = 0
            good, why, kind = self.challenge.check_solution(form.get("t", ""), form.get("n", ""), form.get("m", ""),
                                                            moves, c["site"], c["ip"], c["ua"])
        print(f"verify site={c['site']} type={kind} ip={c['ip']} result={'pass' if good else 'fail'} ({why})",
              flush=True)
        if not good:
            if why == "wrong answer":
                return self.issue(c, ret, notice=WRONG_NOTICE.get(kind, ""))
            if why in ("token expired", "token already used"):
                return self.issue(c, ret, notice="The check timed out. It's been restarted.")
            ray = secrets.token_hex(8)
            return self.send(403, challenge_page("failed", c["host"] or c["site"], ray, return_to=ret))
        value = self.challenge.make_pass(c["site"], c["ip"], c["ua"], c["ttl"], c["bind_ip"])
        cookie = f"{COOKIE_NAME}={value}; Path=/; HttpOnly; SameSite=Lax"
        if c["ttl"] > 0:
            cookie += f"; Max-Age={c['ttl']}"   # ttl 0: no Max-Age = gone when the browser closes
        if c["secure"]:
            cookie += "; Secure"
        self.send(303, "", headers={"Set-Cookie": cookie, "Location": ret})

    do_GET = do_POST = do_HEAD = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = route


def cmd_serve(args):
    g = load_json(GLOBAL_CONF, DEFAULT_GLOBAL)
    listen = args.listen or g["listen"]
    host, _, port = listen.rpartition(":")
    Handler.challenge = Challenge(load_secret())
    ThreadingHTTPServer.daemon_threads = True
    srv = ThreadingHTTPServer((host.strip("[]") or "127.0.0.1", int(port)), Handler)
    print(f"easywaf {VERSION} challenge service listening on {listen}", flush=True)
    srv.serve_forever()


# --------------------------------------------------------------------------
# nginx configuration
# --------------------------------------------------------------------------

def site_path(domain):
    return os.path.join(SITES_DIR, f"{domain}.json")


def nginx_path(domain):
    return os.path.join(NGINX_SITES_DIR, f"{domain}.conf")


def load_site(domain):
    p = site_path(domain)
    if not os.path.exists(p):
        die(f"site '{domain}' does not exist (see: easywaf list)")
    return load_json(p, DEFAULT_SITE)


def all_sites():
    if not os.path.isdir(SITES_DIR):
        return []
    return sorted(f[:-5] for f in os.listdir(SITES_DIR) if f.endswith(".json"))


def normalize_backend(url):
    url = url.strip()
    if "://" not in url:
        url = "http://" + url
    u = urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        die(f"invalid backend '{url}' (expected e.g. http://10.0.0.5:8080)")
    if u.path not in ("", "/") or u.query:
        die("backend must be scheme://host[:port] without a path")
    host = u.hostname
    if ":" in host:
        host = f"[{host}]"
    return f"{u.scheme}://{host}" + (f":{u.port}" if u.port else "")


def validate_site(s):
    s["domain"] = s["domain"].lower().strip()
    s["aliases"] = [a.lower().strip() for a in s["aliases"] if a.strip()]
    for h in [s["domain"]] + s["aliases"]:
        if not HOST_RE.match(h):
            die(f"invalid hostname '{h}'")
    s["backend"] = normalize_backend(s["backend"])
    s["difficulty"] = int(s["difficulty"])
    if not 0 <= s["difficulty"] <= MAX_DIFFICULTY:
        die(f"difficulty must be between 0 and {MAX_DIFFICULTY}")
    s["ttl_hours"] = float(s["ttl_hours"])
    if s["ttl_hours"] < 0:
        die("ttl_hours must be 0 (until the browser closes) or more")
    if s["challenge_type"] not in CHALLENGE_TYPES:
        die("challenge_type must be one of: " + ", ".join(CHALLENGE_TYPES))
    if s["waf"] not in ("on", "detect", "off"):
        die("waf must be on, detect or off")
    for ip in s["allow_ips"]:
        try:
            ipaddress.ip_network(ip, strict=False)
        except ValueError:
            die(f"invalid IP/CIDR in allow_ips: '{ip}'")
    for p in s["skip_paths"]:
        if not p.startswith("/") or re.search(r"[\s;{}'\"]", p):
            die(f"invalid skip path '{p}' (must start with / and contain no spaces/quotes)")
    if not re.fullmatch(r"\d+[kKmMgG]?", str(s["max_body"])):
        die("max_body must look like 50m, 1g or 0")
    s["burst"] = int(s["burst"])
    return s


def cert_paths(domain):
    live = os.path.join(LE_LIVE, domain)
    return os.path.join(live, "fullchain.pem"), os.path.join(live, "privkey.pem")


def render_site(s, g):
    d = s["domain"]
    names = " ".join([d] + s["aliases"])
    backend = s["backend"]
    tls = s["tls"] and os.path.exists(cert_paths(d)[0])
    v6 = g.get("ipv6", True)
    svc = g["listen"]
    ttl = int(s["ttl_hours"] * 3600)
    backend_host = urlsplit(backend).hostname

    waf_headers = f"""        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header User-Agent $http_user_agent;
        proxy_set_header X-WAF-Site "{d}";
        proxy_set_header X-WAF-Host $host;
        proxy_set_header X-WAF-Scheme $scheme;
        proxy_set_header X-WAF-Difficulty "{s['difficulty']}";
        proxy_set_header X-WAF-TTL "{ttl}";
        proxy_set_header X-WAF-Type "{s['challenge_type']}";
        proxy_set_header X-WAF-Bind-IP "{1 if s['bind_ip'] else 0}";
        proxy_set_header X-WAF-Block-Automation "{1 if s['block_automation'] else 0}";"""

    proxy = f"""        proxy_pass {backend};
        proxy_http_version 1.1;
        proxy_set_header Host {'$host' if s['preserve_host'] else '$proxy_host'};
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $easywaf_connection_upgrade;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;"""
    if backend.startswith("https://"):
        sni = "$host" if s["preserve_host"] else backend_host
        proxy += f"""
        proxy_ssl_server_name on;
        proxy_ssl_name {sni};
        proxy_ssl_verify off;"""

    modsec = ""
    if g.get("modsecurity"):
        if s["waf"] == "off":
            modsec = "    modsecurity off;\n"
        else:
            modsec = "    modsecurity on;\n"
            if s["waf"] == "detect":
                modsec += "    modsecurity_rules 'SecRuleEngine DetectionOnly';\n"

    gate = ""
    if s["challenge"]:
        if s["allow_ips"]:
            gate += "        satisfy any;\n"
            gate += "".join(f"        allow {ip};\n" for ip in s["allow_ips"])
            gate += "        deny all;\n"
        gate += "        auth_request /__waf_auth;\n        error_page 401 = @waf_challenge;\n"

    skips = "".join(f"""
    location ^~ {p} {{
{proxy}
    }}
""" for p in s["skip_paths"])

    body = f"""    access_log /var/log/nginx/easywaf-{d}.access.log easywaf;
    error_log /var/log/nginx/easywaf-{d}.error.log warn;
    client_max_body_size {s['max_body']};
    server_tokens off;
{modsec}    limit_req zone=easywaf_req burst={s['burst']} nodelay;
    limit_req_status 429;

    # --- EasyWAF browser check ---------------------------------------------
    location = /__waf/verify {{
        limit_req zone=easywaf_verify burst=10 nodelay;
        proxy_pass http://{svc}/verify;
{waf_headers}
    }}

    location = /__waf_auth {{
        internal;
        modsecurity off;
        proxy_pass http://{svc}/auth;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
{waf_headers}
    }}

    location @waf_challenge {{
        modsecurity off;
        rewrite ^ /challenge break;
        proxy_pass http://{svc};
        proxy_set_header X-Original-URI $request_uri;
{waf_headers}
    }}

    # --- paths without browser check -----------------------------------------
{skips}
    # --- everything else: check, then forward to the real site ---------------
    location / {{
{gate}{proxy}
    }}
"""
    if not g.get("modsecurity"):
        body = body.replace("        modsecurity off;\n", "")

    l80 = "    listen 80;\n" + ("    listen [::]:80;\n" if v6 else "")
    acme = f"""    location ^~ /.well-known/acme-challenge/ {{
        root {ACME_ROOT};
        default_type text/plain;
        auth_request off;
    }}
"""
    out = f"# Generated by easywaf for {d} - edit with: easywaf set {d} key=value\n"
    if tls:
        crt, key = cert_paths(d)
        h2 = nginx_version() >= (1, 25, 1)
        flag = "" if h2 else " http2"
        l443 = f"    listen 443 ssl{flag};\n" + (f"    listen [::]:443 ssl{flag};\n" if v6 else "")
        if h2:
            l443 += "    http2 on;\n"
        out += f"""server {{
{l80}    server_name {names};
{acme}    location / {{ return 301 https://$host$request_uri; }}
}}

server {{
{l443}    server_name {names};
    ssl_certificate {crt};
    ssl_certificate_key {key};
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header Strict-Transport-Security "max-age=31536000" always;
{acme}
{body}}}
"""
    else:
        out += f"""server {{
{l80}    server_name {names};
{acme}
{body}}}
"""
    return out


def render_global(g):
    v6 = g.get("ipv6", True)
    modsec = ""
    if g.get("modsecurity"):
        modsec = f"modsecurity_rules_file {ETC}/modsec/main.conf;\n"
    return f"""# Generated by easywaf - global settings (easywaf global key=value)
log_format easywaf '$remote_addr - [$time_local] "$host" "$request" $status $body_bytes_sent '
                   '"$http_referer" "$http_user_agent" rt=$request_time';
map $http_upgrade $easywaf_connection_upgrade {{ default upgrade; '' close; }}
limit_req_zone $binary_remote_addr zone=easywaf_req:20m rate={int(g['rate_per_second'])}r/s;
limit_req_zone $binary_remote_addr zone=easywaf_verify:10m rate=2r/s;
{modsec}
# Unknown hostnames are dropped instead of reaching any backend.
server {{
    listen 80 default_server;
{"    listen [::]:80 default_server;" if v6 else ""}
    server_name _;
    location ^~ /.well-known/acme-challenge/ {{ root {ACME_ROOT}; }}
    location / {{ return 444; }}
}}
server {{
    listen 443 ssl default_server;
{"    listen [::]:443 ssl default_server;" if v6 else ""}
    server_name _;
    ssl_reject_handshake on;
}}

include {NGINX_SITES_DIR}/*.conf;
"""


def render_modsec(g):
    return f"""# Generated by easywaf - ModSecurity base config + OWASP CRS
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
SecRequestBodyLimitAction ProcessPartial
SecResponseBodyAccess Off
SecPcreMatchLimit 100000
SecPcreMatchLimitRecursion 100000
SecTmpDir /tmp/
SecDataDir /tmp/
SecArgumentSeparator &
SecCookieFormat 0
SecStatusEngine Off
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts ABIJDEFHZ
SecAuditLogType Serial
SecAuditLog {LOG_DIR}/modsec_audit.log

Include {g['crs_setup']}
# Your own exclusions (rules that must run before CRS) go here:
Include {ETC}/modsec/custom-before.conf
Include {g['crs_rules']}/*.conf
Include {ETC}/modsec/custom-after.conf
"""


def nginx_version():
    try:
        out = subprocess.run(["nginx", "-v"], capture_output=True, text=True).stderr
        return tuple(int(x) for x in re.search(r"nginx/(\d+)\.(\d+)\.(\d+)", out).groups())
    except Exception:
        return (1, 24, 0)


def nginx_test():
    r = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
    return r.returncode == 0, (r.stderr or r.stdout).strip()


def nginx_reload():
    subprocess.run(["systemctl", "reload", "nginx"], check=False)


def apply_config(changed=None):
    """Write all nginx files, test them, and roll back if nginx rejects them."""
    g = load_json(GLOBAL_CONF, DEFAULT_GLOBAL)
    planned = {NGINX_GLOBAL: render_global(g)}
    if g.get("modsecurity"):
        planned[os.path.join(ETC, "modsec/main.conf")] = render_modsec(g)
        for name in ("custom-before.conf", "custom-after.conf"):
            p = os.path.join(ETC, "modsec", name)
            if not os.path.exists(p):
                planned[p] = "# Custom ModSecurity rules / exclusions\n# e.g. SecRuleRemoveById 942100\n"
    wanted = set()
    for d in all_sites():
        s = load_json(site_path(d), DEFAULT_SITE)
        planned[nginx_path(d)] = render_site(s, g)
        wanted.add(nginx_path(d))

    backup = {}
    for path, content in planned.items():
        backup[path] = open(path).read() if os.path.exists(path) else None
        write_file(path, content)
    stale = []
    if os.path.isdir(NGINX_SITES_DIR):
        for f in os.listdir(NGINX_SITES_DIR):
            p = os.path.join(NGINX_SITES_DIR, f)
            if f.endswith(".conf") and p not in wanted:
                backup[p] = open(p).read()
                os.remove(p)
                stale.append(p)

    good, out = nginx_test()
    if not good:
        for path, content in backup.items():
            if content is None:
                os.remove(path)
            else:
                write_file(path, content)
        print(out, file=sys.stderr)
        return False
    nginx_reload()
    return True


def save_site(s, old=None):
    s = validate_site(s)
    os.makedirs(SITES_DIR, exist_ok=True)
    write_file(site_path(s["domain"]), json.dumps(s, indent=2) + "\n", 0o640)
    if not apply_config():
        if old is None:
            os.remove(site_path(s["domain"]))
        else:
            write_file(site_path(s["domain"]), json.dumps(old, indent=2) + "\n", 0o640)
        apply_config()
        die("nginx rejected the new configuration - change was rolled back")


# --------------------------------------------------------------------------
# CLI commands
# --------------------------------------------------------------------------

def need_root():
    if os.geteuid() != 0:
        die("please run as root (sudo easywaf ...)")


def ask(prompt, default=None, validate=None):
    while True:
        sfx = f" [{default}]" if default not in (None, "") else ""
        try:
            val = input(f"  {prompt}{sfx}: ").strip()
        except EOFError:
            val = ""
        if not val and default is not None:
            val = str(default)
        if val and (validate is None or validate(val)):
            return val
        print("    please enter a valid value")


def yes(prompt, default=True):
    d = "Y/n" if default else "y/N"
    try:
        val = input(f"  {prompt} [{d}]: ").strip().lower()
    except EOFError:
        val = ""
    return default if not val else val.startswith("y")


def split_list(v):
    return [x for x in re.split(r"[,\s]+", v or "") if x]


def cmd_add(a):
    need_root()
    interactive = not (a.domain and a.backend)
    s = dict(DEFAULT_SITE)
    if interactive:
        print("\nAdd a protected site\n")
        s["domain"] = ask("Public domain (e.g. shop.example.com)", a.domain,
                          lambda v: HOST_RE.match(v.lower()) is not None)
        s["aliases"] = split_list(ask("Extra hostnames, comma separated (or - for none)", "-").replace("-", ""))
        s["backend"] = ask("Address of the real site (e.g. http://10.0.0.5:8080)", a.backend)
        s["challenge"] = yes("Show the browser check to visitors?", True)
        if s["challenge"]:
            s["difficulty"] = int(ask("Check difficulty, 12=instant 16=~1s 18=~3s", 16,
                                      lambda v: v.isdigit() and int(v) <= MAX_DIFFICULTY))
            s["challenge_type"] = ask("Type of check: auto (no clicks) / select / click / drag / manual (random)",
                                      "auto", lambda v: v in CHALLENGE_TYPES)
            s["ttl_hours"] = float(ask("Hours a passed check stays valid (0 = until the browser closes)", 24,
                                       lambda v: re.fullmatch(r"\d+(\.\d+)?", v) is not None))
            s["skip_paths"] = split_list(ask("Paths without check, e.g. /api/ /webhooks/ (or - for none)", "-").replace("-", ""))
        s["waf"] = ask("WAF mode: on (block attacks) / detect (log only) / off", "on",
                       lambda v: v in ("on", "detect", "off"))
        want_tls = yes("Get a free HTTPS certificate from Let's Encrypt now? (DNS must point here)", False)
    else:
        s["domain"], s["backend"] = a.domain, a.backend
        s["aliases"] = split_list(a.alias)
        if a.no_challenge:
            s["challenge"] = False
        if a.difficulty is not None:
            s["difficulty"] = a.difficulty
        if a.ttl is not None:
            s["ttl_hours"] = a.ttl
        if a.type:
            s["challenge_type"] = a.type
        s["skip_paths"] = split_list(a.skip)
        if a.waf:
            s["waf"] = a.waf
        want_tls = a.tls
    if os.path.exists(site_path(s["domain"].lower())):
        die(f"site '{s['domain']}' already exists - use: easywaf set {s['domain']} key=value")
    save_site(s)
    ok(f"{s['domain']} is now protected and forwards to {normalize_backend(s['backend'])}")
    if want_tls:
        cmd_tls(argparse.Namespace(domain=s["domain"], email=getattr(a, "email", None), staging=False))
    else:
        info(f"Enable HTTPS later with: sudo easywaf tls {s['domain']}")


def coerce(key, raw):
    default = DEFAULT_SITE.get(key)
    if isinstance(default, bool):
        if raw.lower() in ("1", "true", "yes", "on"):
            return True
        if raw.lower() in ("0", "false", "no", "off"):
            return False
        die(f"{key} expects on/off")
    if isinstance(default, list):
        return split_list(raw)
    if isinstance(default, int):
        return int(raw)
    if isinstance(default, float):
        return float(raw)
    return raw


def cmd_set(a):
    need_root()
    s = load_site(a.domain)
    old = dict(s)
    for pair in a.pairs:
        if "=" not in pair:
            die(f"expected key=value, got '{pair}'")
        k, v = pair.split("=", 1)
        k = k.strip().replace("-", "_")
        if k == "domain":
            die("the domain can't be changed - remove and add the site again")
        if k not in DEFAULT_SITE:
            die(f"unknown setting '{k}'. Valid: {', '.join(x for x in DEFAULT_SITE if x != 'domain')}")
        s[k] = coerce(k, v)
    save_site(s, old)
    ok(f"updated {a.domain}")


def cmd_edit(a):
    need_root()
    s = load_site(a.domain)
    old = dict(s)
    editor = os.environ.get("EDITOR") or shutil.which("nano") or "vi"
    with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False) as f:
        json.dump(s, f, indent=2)
        tmp = f.name
    subprocess.call([editor, tmp])
    try:
        with open(tmp) as f:
            new = json.load(f)
    except json.JSONDecodeError as e:
        die(f"invalid JSON, nothing changed: {e}")
    finally:
        os.unlink(tmp)
    if new.get("domain", "").lower() != a.domain:
        die("the domain can't be changed in edit")
    merged = dict(DEFAULT_SITE)
    merged.update(new)
    save_site(merged, old)
    ok(f"updated {a.domain}")


def cmd_show(a):
    print(json.dumps(load_site(a.domain), indent=2))


def cmd_list(a):
    sites = all_sites()
    if not sites:
        print("No sites yet. Add one with: sudo easywaf add")
        return
    rows = [("DOMAIN", "BACKEND", "HTTPS", "CHECK", "WAF")]
    for d in sites:
        s = load_json(site_path(d), DEFAULT_SITE)
        https = "yes" if s["tls"] and os.path.exists(cert_paths(d)[0]) else ("pending" if s["tls"] else "no")
        ttl = "session" if not s["ttl_hours"] else f"{s['ttl_hours']:g}h"
        check = f"{s['challenge_type']}, {ttl}" if s["challenge"] else "off"
        rows.append((d, s["backend"], https, check, s["waf"]))
    w = [max(len(r[i]) for r in rows) for i in range(5)]
    for i, r in enumerate(rows):
        line = "  ".join(c.ljust(w[j]) for j, c in enumerate(r))
        print(f"\033[1m{line}\033[0m" if i == 0 else line)


def cmd_remove(a):
    need_root()
    load_site(a.domain)
    if not a.yes and not yes(f"Remove {a.domain}? Visitors will no longer reach it through EasyWAF", False):
        return
    os.remove(site_path(a.domain))
    apply_config()
    ok(f"removed {a.domain}")


def cmd_tls(a):
    need_root()
    s = load_site(a.domain)
    if not shutil.which("certbot"):
        die("certbot is not installed (apt install certbot)")
    names = [s["domain"]] + s["aliases"]
    email = a.email or ask("E-mail for Let's Encrypt expiry notices", "")
    os.makedirs(ACME_ROOT, exist_ok=True)
    cmd = ["certbot", "certonly", "--webroot", "-w", ACME_ROOT, "--non-interactive",
           "--agree-tos", "--keep-until-expiring", "--cert-name", s["domain"]]
    cmd += ["--email", email] if email else ["--register-unsafely-without-email"]
    if a.staging:
        cmd.append("--staging")
    for n in names:
        cmd += ["-d", n]
    info("requesting certificate: " + " ".join(names))
    if subprocess.call(cmd) != 0:
        die("certbot failed - check that DNS for the domain points to this server and port 80 is open")
    old = dict(s)
    s["tls"] = True
    save_site(s, old)
    ok(f"https://{s['domain']} is live (auto-renewed by certbot)")


def cmd_global(a):
    need_root()
    g = load_json(GLOBAL_CONF, DEFAULT_GLOBAL)
    if not a.pairs:
        print(json.dumps(g, indent=2))
        return
    old = dict(g)
    for pair in a.pairs:
        k, _, v = pair.partition("=")
        if k not in DEFAULT_GLOBAL:
            die(f"unknown global setting '{k}'")
        d = DEFAULT_GLOBAL[k]
        g[k] = (v.lower() in ("1", "true", "on", "yes")) if isinstance(d, bool) else (int(v) if isinstance(d, int) else v)
    write_file(GLOBAL_CONF, json.dumps(g, indent=2) + "\n")
    if not apply_config():
        write_file(GLOBAL_CONF, json.dumps(old, indent=2) + "\n")
        apply_config()
        die("nginx rejected the configuration - rolled back")
    if old["listen"] != g["listen"]:
        subprocess.call(["systemctl", "restart", "easywaf"])
    ok("global settings updated")


def cmd_rebuild(a):
    need_root()
    if apply_config():
        ok("configuration rebuilt and nginx reloaded")
    else:
        die("nginx rejected the configuration - previous files restored")


def cmd_status(a):
    for unit in ("nginx", "easywaf"):
        r = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True)
        state = r.stdout.strip()
        (ok if state == "active" else warn)(f"{unit}: {state}")
    g = load_json(GLOBAL_CONF, DEFAULT_GLOBAL)
    (ok if g.get("modsecurity") else warn)("ModSecurity + OWASP CRS: " + ("enabled" if g.get("modsecurity") else "not available"))
    good, out = nginx_test()
    (ok if good else warn)("nginx config: " + ("valid" if good else out))
    print()
    cmd_list(a)


def cmd_logs(a):
    if a.what == "waf":
        path = os.path.join(LOG_DIR, "modsec_audit.log")
        os.execvp("tail", ["tail", "-n", "100", "-F", path])
    if a.what == "check":
        os.execvp("journalctl", ["journalctl", "-u", "easywaf", "-n", "100", "-f"])
    if a.what:
        load_site(a.what)
        os.execvp("tail", ["tail", "-n", "100", "-F", f"/var/log/nginx/easywaf-{a.what}.access.log"])
    os.execvp("journalctl", ["journalctl", "-u", "easywaf", "-u", "nginx", "-n", "100", "-f"])


def main():
    p = argparse.ArgumentParser(prog="easywaf", description="EasyWAF - WAF reverse proxy with browser check")
    p.add_argument("--version", action="version", version=f"easywaf {VERSION}")
    sub = p.add_subparsers(dest="cmd", metavar="command")

    s = sub.add_parser("add", help="protect a new site (interactive without arguments)")
    s.add_argument("domain", nargs="?")
    s.add_argument("backend", nargs="?", help="e.g. http://10.0.0.5:8080")
    s.add_argument("--alias", help="extra hostnames, comma separated")
    s.add_argument("--tls", action="store_true", help="request a Let's Encrypt certificate")
    s.add_argument("--email")
    s.add_argument("--no-challenge", action="store_true", help="WAF only, no browser check")
    s.add_argument("--difficulty", type=int)
    s.add_argument("--ttl", type=float, help="hours a passed check is valid (0 = until the browser closes)")
    s.add_argument("--type", choices=["auto", "manual", "select", "click", "drag"],
                   help="auto (no clicks), select pictures, click a symbol, drag a puzzle piece, or manual (random)")
    s.add_argument("--skip", help="paths without check, comma separated (e.g. /api/,/hooks/)")
    s.add_argument("--waf", choices=["on", "detect", "off"])
    s.set_defaults(fn=cmd_add)

    s = sub.add_parser("set", help="change settings: easywaf set example.com difficulty=18 waf=detect")
    s.add_argument("domain")
    s.add_argument("pairs", nargs="+", metavar="key=value")
    s.set_defaults(fn=cmd_set)

    s = sub.add_parser("edit", help="edit a site's settings in your editor")
    s.add_argument("domain")
    s.set_defaults(fn=cmd_edit)

    s = sub.add_parser("show", help="print a site's settings")
    s.add_argument("domain")
    s.set_defaults(fn=cmd_show)

    sub.add_parser("list", help="list protected sites").set_defaults(fn=cmd_list)

    s = sub.add_parser("remove", help="stop protecting a site")
    s.add_argument("domain")
    s.add_argument("-y", "--yes", action="store_true")
    s.set_defaults(fn=cmd_remove)

    s = sub.add_parser("tls", help="get a Let's Encrypt certificate and enable HTTPS")
    s.add_argument("domain")
    s.add_argument("--email")
    s.add_argument("--staging", action="store_true", help="use the Let's Encrypt test CA")
    s.set_defaults(fn=cmd_tls)

    s = sub.add_parser("global", help="show/change global settings (rate_per_second=30)")
    s.add_argument("pairs", nargs="*", metavar="key=value")
    s.set_defaults(fn=cmd_global)

    sub.add_parser("rebuild", help="regenerate all nginx config and reload").set_defaults(fn=cmd_rebuild)
    sub.add_parser("status", help="health of nginx, the check service and all sites").set_defaults(fn=cmd_status)

    s = sub.add_parser("logs", help="follow logs: easywaf logs [domain|waf|check]")
    s.add_argument("what", nargs="?")
    s.set_defaults(fn=cmd_logs)

    s = sub.add_parser("serve", help="run the challenge service (used by systemd)")
    s.add_argument("--listen")
    s.set_defaults(fn=cmd_serve)

    a = p.parse_args()
    if not a.cmd:
        p.print_help()
        return
    a.fn(a)


# --------------------------------------------------------------------------
# check page (copy CHALLENGE_HTML to /etc/easywaf/challenge.html to customize;
# keep the {{...}} placeholders, the form and the script)
# --------------------------------------------------------------------------

CHALLENGE_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Opening {{HOST}}</title>
<style>
:root{
  --paper:#e9eeea; --ink:#1f2d33; --ink-soft:#5b6b70; --rule:#c9d3cf;
  --body:#dbe3df; --chamber:#c3cec9; --plug:#cfd8d4; --steel:#9aaab0; --brass:#c08a2e; --brass-deep:#94661c;
  --ok:#2e7d5b; --bad:#a83f2c; --tile-on:#c08a2e;
  color-scheme:light dark;
}
@media (prefers-color-scheme:dark){:root{
  --paper:#142026; --ink:#e2e8e4; --ink-soft:#93a3a6; --rule:#2b3a41;
  --body:#1c2a31; --chamber:#131e23; --plug:#22323a; --steel:#62757c; --brass:#d7a548; --brass-deep:#a97a26;
  --ok:#5fbf8f; --bad:#e0735e; --tile-on:#d7a548;
}}
*{box-sizing:border-box}
html{background:var(--paper)}
body{margin:0;min-height:100vh;background:var(--paper);color:var(--ink);
  font:17px/1.55 Seravek,"Gill Sans Nova","Gill Sans",Ubuntu,Calibri,"DejaVu Sans",sans-serif;
  font-variant-numeric:tabular-nums;-webkit-font-smoothing:antialiased}
main{max-width:760px;margin:0 auto;padding:clamp(48px,14vh,140px) 24px 40px;min-height:100vh;
  display:flex;flex-direction:column}
.gate{display:grid;grid-template-columns:200px minmax(0,1fr);gap:44px;align-items:start}
.lock{width:100%;height:auto;display:block;margin-top:6px}
h1{font-size:clamp(30px,5.2vw,46px);line-height:1.08;font-weight:600;letter-spacing:-.012em;margin:0 0 14px;
  overflow-wrap:anywhere}
h1 .sub{font-weight:400;color:var(--ink-soft)}
.lede{font-size:19px;line-height:1.5;margin:0 0 22px;max-width:34em;color:var(--ink)}
.notice{margin:0 0 18px;padding-left:12px;border-left:3px solid var(--bad);color:var(--ink)}
.notice:empty{display:none}
.status{display:flex;align-items:center;gap:10px;margin:0;font-size:16px;color:var(--ink-soft)}
.status::before{content:"";width:8px;height:8px;border-radius:50%;background:var(--brass);flex:none;
  animation:pulse 1.1s ease-in-out infinite}
.done .status{color:var(--ok)}
.done .status::before{background:var(--ok);animation:none}
@keyframes pulse{50%{opacity:.25}}

.ask{margin:0 0 14px;font-size:18px}
.ask strong{font-weight:600}
.grid{display:grid;grid-template-columns:repeat(3,minmax(0,104px));gap:6px;margin:0 0 18px}
.tile{position:relative;padding:0;border:0;background:none;cursor:pointer;border-radius:7px;aspect-ratio:1;
  outline:2px solid transparent;outline-offset:2px;transition:outline-color .12s}
.tile img{display:block;width:100%;height:100%;border-radius:7px;transition:transform .14s ease,filter .14s}
.tile[aria-pressed=true]{outline-color:var(--tile-on)}
.tile[aria-pressed=true] img{transform:scale(.86);filter:saturate(.75)}
.tile .mark{position:absolute;top:-6px;right:-6px;width:24px;height:24px;border-radius:50%;
  background:var(--tile-on);display:none}
.tile .mark::after{content:"";position:absolute;left:8px;top:4px;width:6px;height:11px;
  border:solid var(--paper);border-width:0 3px 3px 0;transform:rotate(45deg)}
.tile[aria-pressed=true] .mark{display:block}
.tile:focus-visible{outline:3px solid var(--ink)}
.actions{display:flex;flex-wrap:wrap;align-items:center;gap:8px 22px}
.primary{font:inherit;font-weight:600;font-size:16px;padding:11px 22px;border-radius:8px;border:0;cursor:pointer;
  background:var(--ink);color:var(--paper);text-decoration:none;display:inline-block}
.primary:hover{background:color-mix(in srgb,var(--ink) 85%,var(--brass))}
.primary:focus-visible,.again:focus-visible{outline:3px solid var(--brass);outline-offset:3px}
.primary[disabled]{opacity:.6;cursor:progress}
.again{color:var(--ink-soft);font-size:15px;text-underline-offset:3px}
.again:hover{color:var(--ink)}
.hint{min-height:1.5em;margin:12px 0 0;font-size:15px;color:var(--bad)}

.foot{margin-top:auto;padding-top:56px;font-size:14px;color:var(--ink-soft);max-width:42em}
.foot p{margin:0 0 4px}
.foot .by{font-size:13px;opacity:.8}

.m-auto,.m-manual,.m-failed{display:none}
.mode-auto .m-auto,.mode-failed .m-failed,
.mode-select .m-manual,.mode-click .m-manual,.mode-drag .m-manual{display:block}
.mode-auto .status.m-auto,.mode-failed .actions.m-failed{display:flex}
.mode-select .lede,.mode-click .lede,.mode-drag .lede{margin-bottom:18px}

/* click: one picture, pick the right symbol */
.scene,.puzzle{position:relative;width:min(100%,432px);margin:0 0 16px;border-radius:8px;overflow:hidden;
  touch-action:none;-webkit-user-select:none;user-select:none}
.scene img,.puzzle img{display:block;width:100%;height:auto;-webkit-user-drag:none}
.scene{cursor:crosshair}
.pick-mark{position:absolute;width:36px;height:36px;margin:-18px 0 0 -18px;border-radius:50%;pointer-events:none;
  border:3px solid var(--tile-on);box-shadow:0 0 0 2px var(--paper),inset 0 0 0 2px var(--paper)}
/* drag: slide the piece into the gap */
.puzzle .piece{position:absolute;top:calc(var(--gy) * 100% / 144);left:calc(var(--x,0) * 100% / 288);
  width:calc(44 * 100% / 288);cursor:grab;filter:drop-shadow(0 2px 5px rgba(0,0,0,.5))}
.track{position:relative;width:min(100%,432px);height:42px;margin:0 0 18px;border-radius:21px;
  background:var(--body);border:1px solid var(--rule);touch-action:none}
.knob{position:absolute;top:4px;left:calc(4px + (100% - 68px) * var(--x,0) / 244);width:60px;height:32px;
  border:0;border-radius:16px;background:var(--ink);cursor:grab;padding:0}
.knob span,.knob span::before,.knob span::after{position:absolute;top:9px;width:2px;height:14px;border-radius:1px;
  background:var(--paper);content:""}
.knob span{left:29px}.knob span::before{left:-7px;top:0}.knob span::after{left:7px;top:0}
.knob:focus-visible{outline:3px solid var(--brass);outline-offset:3px}
.dragging,.dragging *{cursor:grabbing!important}

/* the lock: pins drop into line, then the plug turns */
.pin{transition:transform .45s cubic-bezier(.3,1.5,.5,1)}
.pin.set{transform:translateY(0)!important}
.plug{transition:transform .5s cubic-bezier(.5,0,.2,1) .15s}
.shear{stroke:var(--ink-soft);stroke-dasharray:3 4;transition:stroke .3s}
.open .plug{transform:translateX(7px)}
.open .shear{stroke:var(--ok);stroke-dasharray:none;stroke-width:2.5}
.mode-failed .shear{stroke:var(--bad)}

@media (max-width:620px){
  main{padding-top:40px}
  .gate{grid-template-columns:1fr;gap:22px}
  .lock{width:150px;margin:0}
  .mode-select .lock,.mode-click .lock,.mode-drag .lock{width:110px}
  .grid{grid-template-columns:repeat(3,minmax(0,1fr));max-width:330px}
}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
</style>
</head>
<body class="mode-{{MODE}}">
<main>
  <div class="gate" id="gate">
    <svg class="lock" viewBox="0 0 220 130" role="img" aria-label="Lock">
      <defs>
        <clipPath id="c0"><rect x="37" y="16" width="18" height="96"/></clipPath>
        <clipPath id="c1"><rect x="69" y="16" width="18" height="96"/></clipPath>
        <clipPath id="c2"><rect x="101" y="16" width="18" height="96"/></clipPath>
        <clipPath id="c3"><rect x="133" y="16" width="18" height="96"/></clipPath>
        <clipPath id="c4"><rect x="165" y="16" width="18" height="96"/></clipPath>
      </defs>
      <rect x="12" y="10" width="196" height="110" rx="14" fill="var(--body)" stroke="var(--ink)" stroke-width="2"/>
      <g fill="var(--chamber)">
        <rect x="37" y="16" width="18" height="52" rx="2"/><rect x="69" y="16" width="18" height="52" rx="2"/>
        <rect x="101" y="16" width="18" height="52" rx="2"/><rect x="133" y="16" width="18" height="52" rx="2"/>
        <rect x="165" y="16" width="18" height="52" rx="2"/>
      </g>
      <!-- driver pins + springs (stay in the housing) -->
      <g fill="var(--steel)" stroke="var(--ink-soft)" stroke-width="1.6" stroke-linejoin="round">
        <g clip-path="url(#c0)"><g class="pin" style="transform:translateY(9px)"><polyline fill="none" points="41,16 51,20 41,24 51,28 41,32 51,36 41,40 46,44"/><rect x="40" y="44" width="12" height="22" rx="2" stroke="none"/></g></g>
        <g clip-path="url(#c1)"><g class="pin" style="transform:translateY(-8px)"><polyline fill="none" points="73,16 83,20 73,24 83,28 73,32 83,36 73,40 78,44"/><rect x="72" y="44" width="12" height="22" rx="2" stroke="none"/></g></g>
        <g clip-path="url(#c2)"><g class="pin" style="transform:translateY(12px)"><polyline fill="none" points="105,16 115,20 105,24 115,28 105,32 115,36 105,40 110,44"/><rect x="104" y="44" width="12" height="22" rx="2" stroke="none"/></g></g>
        <g clip-path="url(#c3)"><g class="pin" style="transform:translateY(-10px)"><polyline fill="none" points="137,16 147,20 137,24 147,28 137,32 147,36 137,40 142,44"/><rect x="136" y="44" width="12" height="22" rx="2" stroke="none"/></g></g>
        <g clip-path="url(#c4)"><g class="pin" style="transform:translateY(7px)"><polyline fill="none" points="169,16 179,20 169,24 179,28 169,32 179,36 169,40 174,44"/><rect x="168" y="44" width="12" height="22" rx="2" stroke="none"/></g></g>
      </g>
      <!-- the plug: key pins + key, turns when every pin sits on the line -->
      <g class="plug">
        <rect x="20" y="66" width="180" height="46" rx="6" fill="var(--plug)"/>
        <g fill="var(--brass)">
          <g clip-path="url(#c0)"><rect class="pin" style="transform:translateY(9px)" x="40" y="66" width="12" height="20" rx="3"/></g>
          <g clip-path="url(#c1)"><rect class="pin" style="transform:translateY(-8px)" x="72" y="66" width="12" height="14" rx="3"/></g>
          <g clip-path="url(#c2)"><rect class="pin" style="transform:translateY(12px)" x="104" y="66" width="12" height="24" rx="3"/></g>
          <g clip-path="url(#c3)"><rect class="pin" style="transform:translateY(-10px)" x="136" y="66" width="12" height="17" rx="3"/></g>
          <g clip-path="url(#c4)"><rect class="pin" style="transform:translateY(7px)" x="168" y="66" width="12" height="11" rx="3"/></g>
        </g>
        <path fill="var(--brass-deep)" d="M22 106 V92 L36 91 L46 86 L56 91 L68 85 L78 80 L88 86 L100 91 L110 90 L120 91 L132 87 L142 83 L152 87 L164 82 L174 77 L184 82 L198 90 V106 Z"/>
      </g>
      <line class="shear" x1="20" y1="66" x2="200" y2="66"/>
    </svg>

    <div class="copy">
      <h1>{{HOST_HTML}}</h1>
      <p class="lede m-auto">Checking that you're a person before opening the site. This takes a moment.</p>
      <p class="lede m-manual">One quick question before the site opens.</p>
      <p class="lede m-failed">Your browser couldn't be checked. This can happen when the page stays open too long,
        your network changes, or the browser is controlled by automation software.</p>
      <p class="notice" role="alert">{{NOTICE}}</p>

      <p class="status m-auto" id="status" aria-live="polite">Checking your browser</p>

      <div class="m-manual">
        <p class="ask" id="ask">{{PROMPT_HTML}}</p>
        {{CHALLENGE}}
        <div class="actions">
          <button type="button" class="primary" id="go">Verify</button>
          <a class="again" href="{{RETURN}}">Show different pictures</a>
        </div>
        <p class="hint" id="hint" aria-live="polite"></p>
      </div>

      <div class="m-failed actions"><a class="primary" href="{{RETURN}}">Try again</a></div>
      <noscript><p class="notice">Turn on JavaScript, then reload this page to continue.</p></noscript>
    </div>
  </div>

  <div class="foot">
    <p>Reference {{RAY}}. If this page keeps coming back, send this reference to the people who run {{HOST}}.</p>
    <p class="by">Screened by EasyWAF</p>
  </div>

  <form id="f" method="POST" action="/__waf/verify" hidden>
    <input type="hidden" name="t" value="{{TOKEN}}">
    <input type="hidden" name="n" id="n">
    <input type="hidden" name="m" id="m">
    <input type="hidden" name="e" id="e" value="0">
    <input type="hidden" name="wd" id="wd" value="0">
    <input type="hidden" name="r" value="{{RETURN}}">
  </form>
</main>
<script>
(function(){
  var mode=document.body.className.replace('mode-',''), manual=mode!=='auto';
  if(mode==='failed')return;
  var TOKEN=document.querySelector('input[name=t]').value, BITS={{DIFFICULTY}};
  var K=[],H=[],p=2,c=0;
  function frac(x){return (x-Math.floor(x))*4294967296|0}
  while(c<64){var isP=true;for(var q=2;q*q<=p;q++)if(p%q==0){isP=false;break}
    if(isP){if(c<8)H[c]=frac(Math.pow(p,1/2));K[c]=frac(Math.pow(p,1/3));c++}p++}
  var W=new Int32Array(64);
  function sha(msg){ // ASCII-only SHA-256, returns first two words
    var l=msg.length,nb=((l+8)>>6)+1,M=new Int32Array(nb*16),i;
    for(i=0;i<l;i++)M[i>>2]|=msg.charCodeAt(i)<<(24-(i&3)*8);
    M[l>>2]|=0x80<<(24-(l&3)*8);M[nb*16-1]=l*8;
    var h0=H[0],h1=H[1],h2=H[2],h3=H[3],h4=H[4],h5=H[5],h6=H[6],h7=H[7];
    for(var b=0;b<nb;b++){
      for(i=0;i<16;i++)W[i]=M[b*16+i];
      for(i=16;i<64;i++){var x=W[i-15],y=W[i-2];
        W[i]=(W[i-16]+((x>>>7|x<<25)^(x>>>18|x<<14)^(x>>>3))+W[i-7]+((y>>>17|y<<15)^(y>>>19|y<<13)^(y>>>10)))|0}
      var a=h0,e1=h1,d=h2,e=h3,f=h4,g=h5,k=h6,m=h7;
      for(i=0;i<64;i++){
        var t1=(m+((f>>>6|f<<26)^(f>>>11|f<<21)^(f>>>25|f<<7))+((f&g)^(~f&k))+K[i]+W[i])|0;
        var t2=(((a>>>2|a<<30)^(a>>>13|a<<19)^(a>>>22|a<<10))+((a&e1)^(a&d)^(e1&d)))|0;
        m=k;k=g;g=f;f=(e+t1)|0;e=d;d=e1;e1=a;a=(t1+t2)|0}
      h0=(h0+a)|0;h1=(h1+e1)|0;h2=(h2+d)|0;h3=(h3+e)|0;h4=(h4+f)|0;h5=(h5+g)|0;h6=(h6+k)|0;h7=(h7+m)|0}
    return [h0,h1];
  }
  function zeros(h){var z=Math.clz32(h[0]);return z<32?z:32+Math.clz32(h[1])}

  var pins=[].slice.call(document.querySelectorAll('.lock .pin')), gate=document.getElementById('gate');
  var set=0, solved=false, waiting=false, nonce=0, start=Date.now(), expected=Math.pow(2,BITS);
  function setPins(nv){ // pins i and i+5 are the driver and key pin of one stack
    while(set<nv&&set<5){pins[set].classList.add('set');pins[set+5].classList.add('set');set++}
  }
  if(navigator.webdriver)document.getElementById('wd').value='1';
  function submit(){
    setPins(5);
    document.getElementById('n').value=String(nonce);
    setTimeout(function(){gate.classList.add('open');document.body.classList.add('done')},250);
    setTimeout(function(){document.getElementById('f').submit()},manual?650:1000);
  }
  function solvedNow(){
    solved=true;
    if(!manual){
      var wait=Math.max(0,1300-(Date.now()-start)); // keep the check visible for a moment
      setTimeout(function(){document.getElementById('status').textContent='Checked. Opening the site.';submit()},wait);
    }else if(waiting){submit()}
  }
  function work(){
    var stop=Date.now()+40;
    while(Date.now()<stop){
      for(var j=0;j<2000;j++){
        if(zeros(sha(TOKEN+':'+nonce))>=BITS){solvedNow();return}
        nonce++}
    }
    if(!manual)setPins(Math.floor(5*(1-Math.exp(-nonce/expected))));
    setTimeout(work,0);
  }
  if(!navigator.cookieEnabled){
    var s=document.getElementById('status');if(s)s.textContent='Cookies are turned off.';
    var h=document.querySelector('.notice');h.textContent='Turn on cookies for this site, then reload the page.';return;
  }
  var answer=function(){return null}, moves=0, hint=document.getElementById('hint');
  if(mode==='select'){
    var tiles=[].slice.call(document.querySelectorAll('.tile'));
    tiles.forEach(function(t){t.addEventListener('click',function(){
      t.setAttribute('aria-pressed',t.getAttribute('aria-pressed')==='true'?'false':'true');
      var picked=tiles.filter(function(x){return x.getAttribute('aria-pressed')==='true'}).length;
      setPins(Math.min(4,picked));hint.textContent='';
    })});
    answer=function(){var m=tiles.map(function(t){return t.getAttribute('aria-pressed')==='true'?'1':'0'}).join('');
      return m.indexOf('1')<0?null:m};
    hint.dataset.empty='Select at least one picture first.';
  }
  if(mode==='click'){
    var scene=document.getElementById('scene'), simg=scene.querySelector('img'), mark=scene.querySelector('.pick-mark'), at=null;
    scene.addEventListener('pointerdown',function(ev){
      var r=simg.getBoundingClientRect(), x=(ev.clientX-r.left)/r.width, y=(ev.clientY-r.top)/r.height;
      if(x<0||x>1||y<0||y>1)return;
      at=Math.round(x*simg.naturalWidth)+','+Math.round(y*simg.naturalHeight);
      mark.style.left=(x*100)+'%';mark.style.top=(y*100)+'%';mark.hidden=false;setPins(4);hint.textContent='';
    });
    answer=function(){return at};
    hint.dataset.empty='Click a symbol in the picture first.';
  }
  if(mode==='drag'){
    var pz=document.getElementById('puzzle'), pimg=pz.querySelector('img'), track=document.getElementById('track'),
        knob=document.getElementById('knob'), MAX=244, x=0;
    function place(v){x=Math.max(0,Math.min(MAX,v));pz.style.setProperty('--x',x);track.style.setProperty('--x',x);
      knob.setAttribute('aria-valuenow',Math.round(x));moves++;if(moves>2)setPins(4);hint.textContent=''}
    function grab(el,scale){
      el.addEventListener('pointerdown',function(ev){
        ev.preventDefault();var sx=ev.clientX, x0=x, k=scale();
        document.body.classList.add('dragging');
        function mv(e){place(x0+(e.clientX-sx)*k)}
        function up(){document.removeEventListener('pointermove',mv);document.removeEventListener('pointerup',up);
          document.removeEventListener('pointercancel',up);document.body.classList.remove('dragging')}
        document.addEventListener('pointermove',mv);document.addEventListener('pointerup',up);
        document.addEventListener('pointercancel',up);
      });
    }
    grab(knob,function(){return MAX/Math.max(1,track.clientWidth-68)});
    grab(document.getElementById('piece'),function(){return pimg.naturalWidth/pimg.clientWidth});
    knob.addEventListener('keydown',function(ev){
      var step=ev.shiftKey?10:2;
      if(ev.key==='ArrowRight'){place(x+step);ev.preventDefault()}
      if(ev.key==='ArrowLeft'){place(x-step);ev.preventDefault()}
      if(ev.key==='Enter'){document.getElementById('go').click();ev.preventDefault()}
    });
    answer=function(){return moves<3?null:String(Math.round(x))};
    hint.dataset.empty='Move the piece into the gap first.';
  }
  if(manual){
    var go=document.getElementById('go');
    go.addEventListener('click',function(){
      var a=answer();
      if(a===null){hint.textContent=hint.dataset.empty;return}
      document.getElementById('m').value=a;document.getElementById('e').value=String(moves);
      go.disabled=true;go.textContent='Verifying';
      waiting=true;if(solved)submit();
    });
  }
  setTimeout(work,60);
})();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    main()
EASYWAF_PY_EOF
chmod 755 "$PREFIX/easywaf.py"
ln -sf "$PREFIX/easywaf.py" /usr/local/bin/easywaf
c_ok "easywaf command installed"

# --- secret + global config (kept on re-install) ------------------------------
if [ ! -s "$ETC/secret.key" ]; then
  python3 -c 'import secrets;print(secrets.token_hex(32))' > "$ETC/secret.key"
fi
chown root:easywaf "$ETC/secret.key"; chmod 640 "$ETC/secret.key"

python3 - "$ETC/config.json" "$MODSEC" "$IPV6" "$CRS_SETUP" "$CRS_RULES" <<'PY'
import json, sys, os
path, modsec, ipv6, setup, rules = sys.argv[1:]
cfg = {}
if os.path.exists(path):
    cfg = json.load(open(path))
cfg.setdefault("listen", "127.0.0.1:8099")
cfg.setdefault("rate_per_second", 20)
cfg["modsecurity"] = modsec == "true"
cfg["ipv6"] = ipv6 == "true"
cfg["crs_setup"] = setup
cfg["crs_rules"] = rules
json.dump(cfg, open(path, "w"), indent=2)
PY

# --- nginx: our own default server replaces Ubuntu's welcome page -------------
if [ -L /etc/nginx/sites-enabled/default ]; then
  rm -f /etc/nginx/sites-enabled/default
  c_info "disabled nginx's default welcome site"
fi

# --- systemd service for the challenge service ---------------------------------
cat > /etc/systemd/system/easywaf.service <<'UNIT'
[Unit]
Description=EasyWAF browser check service
After=network.target
Before=nginx.service

[Service]
ExecStart=/usr/bin/python3 /opt/easywaf/easywaf.py serve
User=easywaf
Group=easywaf
Restart=always
RestartSec=2
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
ReadOnlyPaths=/etc/easywaf

[Install]
WantedBy=multi-user.target
UNIT

# --- reload nginx after certificate renewals -----------------------------------
install -d /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/easywaf-reload.sh <<'HOOK'
#!/bin/sh
systemctl reload nginx
HOOK
chmod 755 /etc/letsencrypt/renewal-hooks/deploy/easywaf-reload.sh

systemctl daemon-reload
systemctl enable --now easywaf >/dev/null 2>&1
systemctl restart easywaf
systemctl enable nginx >/dev/null 2>&1
systemctl start nginx 2>/dev/null || true
easywaf rebuild >/dev/null || c_err "nginx did not accept the configuration (run: nginx -t)"
c_ok "nginx and the check service are running"

# --- firewall -------------------------------------------------------------------
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow 80/tcp >/dev/null && ufw allow 443/tcp >/dev/null
  c_ok "opened ports 80 and 443 in ufw"
fi

echo
c_ok "EasyWAF is installed."
echo
if [ "$PROMPT" = 1 ] && [ -e /dev/tty ] && [ -z "$(ls -A "$ETC/sites")" ]; then
  if (exec </dev/tty) 2>/dev/null; then
    printf '  Add your first protected site now? [Y/n]: '
    read -r reply </dev/tty || reply=n
    case "${reply:-y}" in
      [Yy]*) easywaf add </dev/tty || true ;;
    esac
  fi
fi

cat <<'HELP'

  Quick reference
  ───────────────
  sudo easywaf add                              add a site (asks questions)
  sudo easywaf add shop.example.com http://10.0.0.5:8080 --tls --email you@example.com
  sudo easywaf list                             show all sites
  sudo easywaf set shop.example.com difficulty=18 skip_paths=/api/,/hooks/
  sudo easywaf set shop.example.com waf=detect  log attacks only (for testing)
  sudo easywaf tls shop.example.com             enable HTTPS (Let's Encrypt)
  sudo easywaf status                           health check
  sudo easywaf logs shop.example.com            follow access log
  sudo easywaf logs waf                         follow blocked attacks

HELP
