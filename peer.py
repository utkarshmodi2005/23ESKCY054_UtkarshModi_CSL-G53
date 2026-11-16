"""
peer.py - Command-line program for one peer.

  python peer.py --home alice init --name Alice          create identity keys
  python peer.py --home alice whoami                      show my fingerprint
  python peer.py --home bob receive --port 5050           wait for files
  python peer.py --home alice send notes.pdf --to 192.168.1.20:5050

Each peer keeps its data in its own folder (--home):
  identity.pem      RSA-3072 private key, encrypted with a password
  public.pem        public key (may be shared)
  peer.json         this peer's name
  known_peers.json  names and fingerprints of trusted peers

The password is asked for (hidden), or taken from P2P_PASSWORD for scripts.
Test only on your own computer or your own hotspot / home network.
"""

import argparse
import getpass
import json
import os
import socket
import sys

import crypto_utils as cu
import protocol as pr
import transfer as tr


def password(prompt="Identity password: "):
    return os.environ.get("P2P_PASSWORD") or getpass.getpass(prompt)


def load_me(home):
    try:
        with open(os.path.join(home, "peer.json"), encoding="utf-8") as f:
            name = json.load(f)["name"]
    except OSError:
        sys.exit(f"No identity in '{home}'. Run: python peer.py --home {home} init --name <name>")
    return name, cu.load_identity(os.path.join(home, "identity.pem"), password())


def make_trust(home, auto_accept):
    def ask(name, fp):
        print(f"\nNew peer '{name}' with key fingerprint\n    {fp}")
        if auto_accept:
            print("  accepted automatically (--accept-new)")
            return True
        print("Compare this with the fingerprint the peer reads out to you.")
        return input("Trust this peer? [y/N] ").strip().lower() == "y"
    return pr.TrustStore(os.path.join(home, "known_peers.json"), ask)


def progress_bar(done, total, width=30):
    frac = done / total if total else 1
    sys.stdout.write(f"\r  [{'#' * int(frac * width):<{width}}] {frac * 100:5.1f}%  {done:,}/{total:,} bytes")
    if done >= total:
        sys.stdout.write("\n")
    sys.stdout.flush()


# --------------------------------------------------------------- commands
def cmd_init(a):
    os.makedirs(a.home, exist_ok=True)
    key_path = os.path.join(a.home, "identity.pem")
    if os.path.exists(key_path) and not a.force:
        sys.exit("Identity already exists (use --force to replace it).")
    key = cu.new_identity()
    cu.save_identity(key, key_path, password("New identity password (8+ chars): "))
    with open(os.path.join(a.home, "public.pem"), "wb") as f:
        f.write(cu.public_pem(key.public_key()))
    with open(os.path.join(a.home, "peer.json"), "w", encoding="utf-8") as f:
        json.dump({"name": a.name}, f)
    print(f"Created identity for '{a.name}' (RSA-{cu.RSA_BITS})")
    print(f"Fingerprint: {cu.fingerprint(key.public_key())}")


def cmd_whoami(a):
    name, key = load_me(a.home)
    print(f"{name}  {cu.fingerprint(key.public_key())}")


def cmd_trust(a):
    pr.TrustStore(os.path.join(a.home, "known_peers.json")).add(a.name, a.fingerprint.upper())
    print(f"Trusted '{a.name}' = {a.fingerprint.upper()}")


def cmd_receive(a):
    name, key = load_me(a.home)
    trust = make_trust(a.home, a.accept_new)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((a.bind, a.port))
    server.listen(1)
    print(f"{name} ({cu.fingerprint(key.public_key())})")
    print(f"Waiting for files on {a.bind}:{a.port}, saving to '{a.out}'  (Ctrl+C to stop)")
    try:
        while True:
            conn, addr = server.accept()
            with conn:
                conn.settimeout(60)
                print(f"\nConnection from {addr[0]}:{addr[1]}")
                try:
                    s = pr.server_handshake(conn, name, key, trust)
                    print(f"Authenticated '{s.peer_name}' ({s.peer_fp}); AES-256-GCM session ready")
                    tr.receive_files(conn, s, a.out, progress_bar if a.progress else None)
                    print("Session closed by sender.")
                except (pr.ProtocolError, OSError, ValueError) as exc:
                    print(f"REJECTED: {exc}")
                    tr.send_error(conn, str(exc))
            if a.once:
                break
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.close()


def cmd_send(a):
    name, key = load_me(a.home)
    host, _, port = a.to.rpartition(":")
    for path in a.files:
        if not os.path.isfile(path):
            sys.exit(f"Not a file: {path}")
    try:
        with pr.connect(host, int(port)) as sock:
            s = pr.client_handshake(sock, name, key, make_trust(a.home, a.accept_new))
            print(f"Connected to '{s.peer_name}' ({s.peer_fp}); mutual authentication OK")
            for path in a.files:
                print(f"Sending {os.path.basename(path)}")
                r = tr.send_file(sock, s, path, progress_bar)
                speed = r["size"] / 1e6 / r["seconds"] if r["seconds"] else 0
                status = "verified by receiver" if r["ok"] else "REJECTED by receiver (hash mismatch)"
                print(f"  SHA-256 {r['local_sha256']}\n  {status}, {r['seconds']:.2f} s, {speed:.1f} MB/s")
            tr.say_bye(sock, s)
    except (pr.ProtocolError, OSError, ValueError) as exc:
        print(f"\nFAILED: {exc}")
        return 1
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="Authenticated encrypted P2P file sharing")
    p.add_argument("--home", default="peer_data", help="folder with this peer's keys")
    sub = p.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init"); i.add_argument("--name", required=True); i.add_argument("--force", action="store_true")
    sub.add_parser("whoami")
    t = sub.add_parser("trust"); t.add_argument("name"); t.add_argument("fingerprint")
    r = sub.add_parser("receive")
    r.add_argument("--port", type=int, default=5050); r.add_argument("--bind", default="0.0.0.0")
    r.add_argument("--out", default="received"); r.add_argument("--once", action="store_true")
    r.add_argument("--accept-new", action="store_true"); r.add_argument("--progress", action="store_true")
    s = sub.add_parser("send")
    s.add_argument("files", nargs="+"); s.add_argument("--to", required=True, help="HOST:PORT")
    s.add_argument("--accept-new", action="store_true")
    a = p.parse_args(argv)
    return {"init": cmd_init, "whoami": cmd_whoami, "trust": cmd_trust,
            "receive": cmd_receive, "send": cmd_send}[a.cmd](a) or 0


if __name__ == "__main__":
    sys.exit(main())
