#!/usr/bin/env python3
"""SUAIJP (Sorry, uBlock Ain't In JACB, Punk) - JACB's content blocker. Turns uBlock Origin / EasyList filter lists
into the WebKit content blocker JSON that JACB loads from
~/.config/jacb/filters.json.

  python3 suaijp.py                  # download uBO's lists and convert
  python3 suaijp.py a.txt b.txt      # convert local list files instead
  python3 suaijp.py -o out.json ...

Covers network filters (||domain^, options like $third-party, $script,
$domain=) and plain cosmetic filters (##.ad). Skips what WebKit can't do:
scriptlets (##+js), procedural cosmetics (:has-text etc), $redirect,
$removeparam, $csp, regex filters.
"""
import argparse
import json
import os
import re
import sys
import urllib.request

BASE = "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/"
LISTS = [
    "filters/filters.txt", "filters/badware.txt", "filters/privacy.txt",
    "filters/unbreak.txt", "thirdparties/easylist/easylist.txt",
    "thirdparties/easylist/easyprivacy.txt",
]
MAX_RULES = 140000   # WebKit's hard cap is 150000
CHUNK = 200          # selectors per css-display-none rule

DEFAULT_TYPES = ["image", "style-sheet", "script", "font", "raw", "media",
                 "svg-document", "popup"]
TYPES = {
    "script": "script", "image": "image", "stylesheet": "style-sheet",
    "css": "style-sheet", "font": "font", "media": "media",
    "xmlhttprequest": "raw", "xhr": "raw", "fetch": "raw", "ping": "raw",
    "websocket": "raw", "popup": "popup",
}
IGNORED_OPTS = {"important"}
DOMAIN_RE = re.compile(r"^[a-z0-9.-]+$")
SEL_BAD_CHARS = re.compile(r"[{};]|/\*")
PSEUDO_OK = {"not", "has", "first-child", "last-child", "nth-child",
             "nth-of-type", "first-of-type", "last-of-type", "only-child",
             "empty"}
PSEUDO_RE = re.compile(r"(?<!:):([a-zA-Z-]+)")

stats = {"network": 0, "exception": 0, "cosmetic": 0, "skipped": 0}


def regex_from_pattern(p):
    domain = p.startswith("||")
    start = p.startswith("|") and not domain
    if domain:
        p = p[2:]
    elif start:
        p = p[1:]
    end = p.endswith("|")
    if end:
        p = p[:-1]
    if len(p) < 3 or not p.isascii():
        return None
    out = ""
    for ch in p:
        if ch == "*":
            out += ".*"
        elif ch == "^":
            out += "[^a-zA-Z0-9_.%-]"
        elif ch in ".+?()[]{}\\|$":
            out += "\\" + ch
        else:
            out += ch
    prefix = r"^[a-z]+://([^/:]+\.)?" if domain else ("^" if start else "")
    return prefix + out + ("$" if end else "")


def parse_domains(spec, sep):
    inc, exc = [], []
    for d in spec.split(sep):
        d = d.strip().lower()
        neg = d.startswith("~")
        d = d.lstrip("~")
        if not DOMAIN_RE.match(d):
            return None
        (exc if neg else inc).append("*" + d)
    if inc and exc:
        return None
    return inc, exc


def parse_network(line):
    exception = line.startswith("@@")
    if exception:
        line = line[2:]
    if line.startswith("/") and (line.endswith("/") or "/$" in line):
        return None  # regex filter
    pat, opts = line, ""
    i = line.rfind("$")
    if i != -1:
        pat, opts = line[:i], line[i + 1:]
    rx = regex_from_pattern(pat)
    if rx is None:
        return None
    inc_t, exc_t, third, case = [], [], None, False
    ifd, unless = [], []
    for o in filter(None, opts.split(",")):
        neg = o.startswith("~")
        k = o.lstrip("~")
        if k in ("third-party", "3p"):
            third = not neg
        elif k in ("first-party", "1p"):
            third = neg
        elif k.startswith("domain="):
            r = parse_domains(k[7:], "|")
            if r is None:
                return None
            ifd, unless = r
        elif k in TYPES:
            (exc_t if neg else inc_t).append(TYPES[k])
        elif k == "match-case":
            case = True
        elif k in IGNORED_OPTS:
            pass
        else:
            return None
    types = sorted(set(inc_t)) if inc_t else [
        t for t in DEFAULT_TYPES if t not in exc_t]
    if not types:
        return None
    trig = {"url-filter": rx, "resource-type": types}
    if case:
        trig["url-filter-is-case-sensitive"] = True
    if third is not None:
        trig["load-type"] = ["third-party" if third else "first-party"]
    if ifd:
        trig["if-domain"] = ifd
    if unless:
        trig["unless-domain"] = unless
    return exception, {"trigger": trig,
                       "action": {"type": "ignore-previous-rules" if exception else "block"}}


def selector_ok(sel):
    if not sel or SEL_BAD_CHARS.search(sel) or not sel.isascii():
        return False
    if "::" in sel:
        return False
    return all(m in PSEUDO_OK for m in PSEUDO_RE.findall(sel))


def parse_cosmetic(line):
    if "##" not in line or any(x in line for x in ("#@#", "#?#", "#$#", "#%#")):
        return None
    doms, sel = line.split("##", 1)
    if sel.startswith("+js(") or not selector_ok(sel):
        return None
    if not doms:
        return ((), ()), sel
    r = parse_domains(doms, ",")
    if r is None:
        return None
    return (tuple(sorted(r[0])), tuple(sorted(r[1]))), sel


def convert(lines):
    blocks, excepts, generic, specific = [], [], [], {}
    for raw in lines:
        line = raw.strip()
        if not line or line[0] in "!" or line.startswith("[Adblock"):
            continue
        if re.search(r"#[@$%?]*#", line):
            c = parse_cosmetic(line)
            if c is None:
                stats["skipped"] += 1
            elif c[0] == ((), ()):
                generic.append(c[1])
                stats["cosmetic"] += 1
            else:
                specific.setdefault(c[0], []).append(c[1])
                stats["cosmetic"] += 1
            continue
        r = parse_network(line)
        if r is None:
            stats["skipped"] += 1
        elif r[0]:
            excepts.append(r[1])
            stats["exception"] += 1
        else:
            blocks.append(r[1])
            stats["network"] += 1

    def hide(sels, ifd=(), unless=()):
        trig = {"url-filter": ".*"}
        if ifd:
            trig["if-domain"] = list(ifd)
        if unless:
            trig["unless-domain"] = list(unless)
        return {"trigger": trig,
                "action": {"type": "css-display-none", "selector": ", ".join(sels)}}

    cosmetic = []
    g = sorted(set(generic))
    for i in range(0, len(g), CHUNK):
        cosmetic.append(hide(g[i:i + CHUNK]))
    for (ifd, unless), sels in specific.items():
        s = sorted(set(sels))
        for i in range(0, len(s), CHUNK):
            cosmetic.append(hide(s[i:i + CHUNK], ifd, unless))

    seen, rules = set(), []
    for r in blocks + excepts:
        k = json.dumps(r, sort_keys=True)
        if k not in seen:
            seen.add(k)
            rules.append(r)
    room = MAX_RULES - len(rules)
    if len(cosmetic) > room:
        print(f"trimming cosmetic rules {len(cosmetic)} -> {max(room, 0)}", file=sys.stderr)
        cosmetic = cosmetic[:max(room, 0)]
    return rules + cosmetic


def read_source(src):
    if os.path.exists(src):
        with open(src, encoding="utf-8", errors="ignore") as f:
            return f.read().splitlines()
    url = src if src.startswith("http") else BASE + src
    print("downloading", url, file=sys.stderr)
    with urllib.request.urlopen(url, timeout=60) as r:
        return r.read().decode("utf-8", "ignore").splitlines()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sources", nargs="*", help="list files or URLs (default: uBO's lists)")
    ap.add_argument("-o", "--out", default=os.path.expanduser("~/.config/jacb/filters.json"))
    a = ap.parse_args()
    lines = []
    for s in a.sources or LISTS:
        try:
            lines += read_source(s)
        except OSError as e:
            print("failed:", s, e, file=sys.stderr)
    rules = convert(lines)
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w") as f:
        json.dump(rules, f, separators=(",", ":"))
    print(f"{len(rules)} rules -> {a.out}  "
          f"(network {stats['network']}, exceptions {stats['exception']}, "
          f"cosmetic {stats['cosmetic']}, skipped {stats['skipped']})")


if __name__ == "__main__":
    main()
