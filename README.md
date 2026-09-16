# ICMP Ping GUI

A Linux desktop app for sending ICMP echo requests, built on a hand-rolled ICMP packet library instead of shelling out to the system `ping` command. It constructs, sends, and parses raw ICMP packets directly in Python, and streams the results live through a GUI built with [Flet](https://flet.dev).

## Features

- Builds and sends ICMP echo request packets manually, including checksum calculation
- Parses and validates replies (packet ID, sequence number, payload)
- Computes packet loss, min/avg/max round-trip time
- Runs without root, using an unprivileged ICMP datagram socket
- Live results — each ping appears as it completes, not all at once at the end
- Ping a fixed count or continuously, with a Stop button to cancel
- Press Enter in the address field to start pinging

## How It Works

The packet logic lives in `icmp_ping_backend.py`:

1. Build an ICMP echo request packet (type 8, code 0)
2. Pack the header, encode a timestamp and payload
3. Calculate the checksum
4. Send it over an unprivileged ICMP datagram socket
5. Receive and validate the matching reply
6. Return a `PingReply` / `PingSummary` dataclass — no console output, so any frontend can use it

`ping_gui.py` runs each ping via `asyncio.to_thread`, so pings don't block the interface, and results are appended to the display as replies arrive.

## Running It

```bash
pip install flet
python ping_gui.py
```

Enter a hostname or IP, hit Ping (or press Enter). Check "Specify ping count" for an exact number, or "Ping until stopped" for a continuous run with a Stop button. Leaving both unchecked defaults to 4 pings.

## Download

A standalone Linux x64 build is available on the [release page](https://github.com/cbourjaily/icmp-ping-gui/releases/tag/v1.0.0):

```bash
tar -xzf icmp-ping-gui-linux-x64-v1.0.0.tar.gz
cd linux
./icmp-helper
```

No Python install or dependencies required.

## Project Structure

```
icmp_ping_backend.py   # ICMP packet construction, sending, parsing — no UI dependencies
ping_gui.py             # Flet GUI, built on the backend
```

The backend has no GUI dependency and returns plain dataclasses, so it's usable standalone from a script or another interface.

## Technical Concepts

- Low-level network programming with Python sockets
- ICMP protocol structure and packet construction
- Binary packing/unpacking with `struct`
- Internet checksum calculation
- Unprivileged ICMP sockets vs. raw sockets
- Async/threaded architecture for a responsive GUI during blocking I/O
- Cooperative cancellation via `threading.Event` across a thread boundary
