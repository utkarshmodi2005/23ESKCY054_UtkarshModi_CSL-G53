"""
attack_proxy.py - A "person in the middle" between two peers, for testing.
Runs ONLY on your own computer: sender -> proxy (listen port) -> receiver.

Modes
  relay    forward everything, save all bytes seen (what a sniffer gets)
  mitm     replace both peers' public keys in HELLO with the attacker's key
  tamper   flip one bit in the 3rd CHUNK frame
  replay   record the sender's frames once, then replay them on the next
           connection instead of the real sender's frames
  drop     cut the connection in the middle of the file

  python tools/attack_proxy.py --listen 6000 --target 127.0.0.1:5050 --mode tamper
"""

import argparse
import json
import os
import socket
import struct
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import crypto_utils as cu  # noqa: E402
from protocol import CHUNK, HELLO  # noqa: E402


def read_frame(sock):
    head = b""
    while len(head) < 4:
        part = sock.recv(4 - len(head))
        if not part:
            return None
        head += part
    (length,) = struct.unpack("!I", head)
    body = b""
    while len(body) < length:
        part = sock.recv(min(65536, length - len(body)))
        if not part:
            return None
        body += part
    return head + body


class AttackProxy:
    def __init__(self, listen_port, target, mode,
                 log=lambda *a: print(*a, flush=True)):
        self.target, self.mode, self.log = target, mode, log
        self.server = socket.socket()
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", listen_port))
        self.server.listen(5)
        self.captured = bytearray()          # every byte that passed through
        self.recorded = []                   # sender frames (for replay)
        self.connections = 0
        self.attacker_key = cu.new_identity() if mode == "mitm" else None

    # -- one direction of one connection
    def pump(self, src, dst, from_sender):
        chunks = 0
        try:
            while True:
                if from_sender and self.mode == "replay" and self.connections > 1:
                    return                    # sender frames come from the recording
                frame = read_frame(src)
                if frame is None:
                    break
                ftype = frame[4]
                if from_sender and self.connections == 1:
                    self.recorded.append(frame)
                if ftype == HELLO and self.mode == "mitm":
                    hello = json.loads(frame[5:])
                    hello["public_key"] = cu.public_pem(self.attacker_key.public_key()).decode()
                    body = bytes([HELLO]) + json.dumps(hello).encode()
                    frame = struct.pack("!I", len(body)) + body
                    self.log(f"[mitm] replaced public key of '{hello['name']}'")
                if ftype == CHUNK and from_sender:
                    chunks += 1
                    if self.mode == "tamper" and chunks == 3:
                        frame = frame[:40] + bytes([frame[40] ^ 0x01]) + frame[41:]
                        self.log("[tamper] flipped one bit in chunk 3")
                    if self.mode == "drop" and chunks == 3:
                        self.log("[drop] cutting the connection")
                        break
                self.captured += frame
                dst.sendall(frame)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def handle(self, client):
        self.connections += 1
        host, port = self.target.rsplit(":", 1)
        upstream = socket.create_connection((host, int(port)))
        if self.mode == "replay" and self.connections > 1:
            self.log(f"[replay] sending {len(self.recorded)} recorded frames")
            for frame in self.recorded:
                upstream.sendall(frame)
        a = threading.Thread(target=self.pump, args=(client, upstream, True), daemon=True)
        b = threading.Thread(target=self.pump, args=(upstream, client, False), daemon=True)
        a.start(); b.start(); a.join(); b.join()
        client.close(); upstream.close()

    def serve(self, count=None):
        handled = 0
        while count is None or handled < count:
            client, _ = self.server.accept()
            self.handle(client)
            handled += 1

    def close(self):
        self.server.close()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--listen", type=int, default=6000)
    p.add_argument("--target", default="127.0.0.1:5050")
    p.add_argument("--mode", choices=["relay", "mitm", "tamper", "replay", "drop"], default="relay")
    p.add_argument("--dump", help="save captured bytes to this file")
    a = p.parse_args()
    proxy = AttackProxy(a.listen, a.target, a.mode)
    print(f"Proxy 127.0.0.1:{a.listen} -> {a.target}  mode={a.mode}  (Ctrl+C to stop)", flush=True)
    try:
        proxy.serve()
    except KeyboardInterrupt:
        pass
    finally:
        if a.dump:
            with open(a.dump, "wb") as f:
                f.write(proxy.captured)
            print(f"Saved {len(proxy.captured):,} captured bytes to {a.dump}")
