# PingEx — ICMP Time-Slot Steganography

Educational **Data Hiding** project that sends **text and files** using plain **ICMP Echo** (`ping`) as a carrier. Bits are encoded by timing: each **50 ms slot** is one bit — **1** = send a ping in that slot, **0** = stay silent.

> ⚠️ For classroom/demo use only. Don’t deploy on networks without permission.

---

## What it does

* UTF-8 **messages** and **file transfer** (name preserved).
* **Framing & sync:** preamble (6 pings), fixed start token `!#-/`, end sentinel `01 05 07`.
* **File mode:** after `!#-/` send `-_-`, then `filename:`, then raw file bits, then `01 05 07`.
* **Robust decoding:** every ping carries a signature (`STG!STG!`) + **16-bit slot index** in payload.
* **Noise control:** server can restrict to a source IP and require the signature.
* **Metrics:** server reports duration and bitrate; client shows ETA for files.
* **No admin on client** (uses OS `ping`). Server uses Scapy (root).

---

## Requirements

* Linux with `ping` supporting `-c`, `-W`, `-s`, `-p <hex>` (e.g., `iputils`).
* Python 3.9+, Scapy on server:

```bash
python3 -m pip install scapy
```

---

## Quick start

**Server (loopback example):**

```bash
sudo python3 server_stegan.py -a 127.0.0.1 --dst 127.0.0.1 --require-sig -i lo -v
```

**Client (message):**

```bash
python3 client_stegan.py 127.0.0.1 --sched-preamble -v
# type your message and press ENTER
```

**Client (file):**

```bash
python3 client_stegan.py 127.0.0.1 --sched-preamble -v --file /path/to/file.pdf
```

The server writes the file to its current directory.

---

## Protocol (short)

* **Physical:** slot `T = 50 ms`, jitter tolerance ≈ **±12.5 ms**.
* **Preamble:** 6 pings (warm-up & sync).
* **Start:** ASCII `!#-/`.
* **Message end:** bytes `01 05 07`.
* **File mode:** `!#-/ -_- filename: <file bits> 01 05 07`.
* **Indexing:** each ping payload = `STG!STG!` + 2-byte slot index (big-endian).
* **Flush:** ≥6 empty slots resets state.

---

## Performance

* Raw rate: `1 / 0.050 s ≈ 20 bit/s`.
* Effective: short messages lower; large files approach \~20 bit/s.

---

## Troubleshooting

* No decode? Check `sudo`, correct interface (`-i lo`/`wlan0`), `--require-sig`, and that `ping -p` exists.
* Truncation? Use `--sched-preamble` and avoid heavy system load.
* File missing? See server `-v` logs for end sentinel and “saved” line, and directory write perms.

---

## Purpose

Built for a **Data Hiding** course to demonstrate timing-based covert channels over common traffic. **Do not use for malicious purposes!**
