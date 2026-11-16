# Authenticated P2P File Sharing (RSA + AES + SHA-256)

Project code: CSL-G53 | Utkarsh Modi (23ESKCY054) | CS-IOT-A-G2
Cyber Security Lab (7CS4-22), SKIT Jaipur | Syllabus project: Secure LAN File Transfer

Two peers on a LAN send files directly to each other:
- each peer has an RSA-3072 identity key (private key saved encrypted)
- peers recognise each other by key fingerprint (known_peers.json, like SSH)
- mutually authenticated handshake: RSA-OAEP wraps a random AES session key,
  both sides sign the handshake transcript with RSA-PSS
- files travel as AES-256-GCM encrypted 64 KB chunks
- the receiver keeps a file only if its SHA-256 matches the sender's

> Test only on your own computer, your own hotspot or home network.

## Setup

    pip install -r requirements.txt

## Two peers (two terminals or two laptops on YOUR hotspot)

    # once per peer
    python peer.py --home alice init --name Alice
    python peer.py --home bob   init --name Bob
    python peer.py --home alice whoami        # read the fingerprints to each other
    python peer.py --home alice trust Bob   <Bob's fingerprint>
    python peer.py --home bob   trust Alice <Alice's fingerprint>

    # receiver (Bob)
    python peer.py --home bob receive --port 5050 --out received --progress

    # sender (Alice); use Bob's LAN IP, e.g. 192.168.43.20
    python peer.py --home alice send report.pdf photo.jpg --to 127.0.0.1:5050

Without the trust step the program shows the fingerprint and asks y/N.
Windows: allow Python through the firewall for port 5050.

## Attack demonstrations (own computer only)

    python peer.py --home bob receive --port 5050                          # terminal 1
    python tools/attack_proxy.py --listen 6000 --target 127.0.0.1:5050 --mode tamper   # terminal 2
    python peer.py --home alice send file.bin --to 127.0.0.1:6000          # terminal 3

Modes: relay (record traffic), mitm (swap public keys), tamper (flip a bit),
replay (replay a recorded session), drop (cut the connection).

## Tests and benchmark

    python -m unittest -v tests/test_p2p.py      # 17 tests over real TCP
    python tools/benchmark.py

## Files

    crypto_utils.py       RSA keys, OAEP, PSS, HKDF, AES-GCM channel, SHA-256
    protocol.py           framing, trusted peers, authenticated handshake
    transfer.py           encrypted chunked transfer, SHA-256 check, safe file names
    peer.py               command-line program (init, whoami, trust, receive, send)
    tools/attack_proxy.py man-in-the-middle / tamper / replay / drop proxy
    tools/benchmark.py    handshake time and throughput
    tests/test_p2p.py     unit tests
