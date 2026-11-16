"""
benchmark.py - Handshake time and transfer speed on this computer
(127.0.0.1, so the network itself is not the bottleneck).

Run:  python tools/benchmark.py
"""

import os
import socket
import statistics
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import crypto_utils as cu  # noqa: E402
import protocol as pr  # noqa: E402
import transfer as tr  # noqa: E402


def main():
    a, b = cu.new_identity(), cu.new_identity()
    folder = tempfile.mkdtemp()
    ta, tb = (pr.TrustStore(os.path.join(folder, n)) for n in ("a.json", "b.json"))
    ta.add("Bob", cu.fingerprint(b.public_key()))
    tb.add("Alice", cu.fingerprint(a.public_key()))

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(50)
    port = srv.getsockname()[1]

    def receiver():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            with conn:
                s = pr.server_handshake(conn, "Bob", b, tb)
                tr.receive_files(conn, s, os.path.join(folder, "in"), log=lambda *_: None)
    threading.Thread(target=receiver, daemon=True).start()

    times = []
    for _ in range(20):
        with pr.connect("127.0.0.1", port) as sock:
            t0 = time.perf_counter()
            s = pr.client_handshake(sock, "Alice", a, ta)
            times.append((time.perf_counter() - t0) * 1000)
            tr.say_bye(sock, s)
    print(f"Handshake (RSA-3072 OAEP + 2 PSS signatures + verify): median {statistics.median(times):.1f} ms"
          f" over {len(times)} runs")

    raw = os.urandom(32 * 1024 * 1024)
    t0 = time.perf_counter()
    import hashlib
    hashlib.sha256(raw).digest()
    print(f"SHA-256 alone: {32 / (time.perf_counter() - t0):.0f} MB/s")

    print(f"\n{'File size':>10} {'Time (s)':>9} {'MB/s':>8} {'Frames':>7} {'Overhead':>9}  Result")
    for mb in (1, 10, 50, 100):
        path = os.path.join(folder, f"f{mb}.bin")
        with open(path, "wb") as f:
            f.write(os.urandom(mb * 1024 * 1024))
        with pr.connect("127.0.0.1", port) as sock:
            s = pr.client_handshake(sock, "Alice", a, ta)
            r = tr.send_file(sock, s, path)
            tr.say_bye(sock, s)
        frames = -(-mb * 1024 * 1024 // tr.CHUNK_SIZE) + 3        # chunks + meta + end + result
        overhead = frames * (5 + 16)                              # frame header + GCM tag
        print(f"{mb:7d} MB {r["seconds"]:9.3f} {mb / r['seconds']:8.1f} {frames:7d}"
              f" {100 * overhead / (mb * 1024 * 1024):8.2f}%  {'hash OK' if r['ok'] else 'FAIL'}")
    srv.close()


if __name__ == "__main__":
    main()
