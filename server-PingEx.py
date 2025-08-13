#!/usr/bin/env python3
from scapy.all import AsyncSniffer, IP, ICMP, Raw
import time, statistics, argparse, ipaddress, os
from collections import deque, defaultdict
from typing import List, Dict, Tuple, Optional, Set

# ===== Especificação do slot =====
NOMINAL_SLOT = 0.050          # 50 ms
NOMINAL_TOL  = 0.0125         # ~25% de 50 ms
PREAMBLE_COUNT = 6
CHECK_INTERVAL = 0.05

# ===== Dedup/robustez =====
PKT_CACHE_TTL = 5.0

# Assinatura "STG!STG!" (default)
DEFAULT_SIG_HEX = "5354472153544721"
DEFAULT_SIG_BYTES = bytes.fromhex(DEFAULT_SIG_HEX)

# ===== Protocolo =====
START_BYTES  = b"!#-/"
END_BYTES    = bytes([0x01,0x05,0x07])
START_BITS   = [(b >> i) & 1 for b in START_BYTES for i in range(7,-1,-1)]
END_BITS     = [(b >> i) & 1 for b in END_BYTES   for i in range(7,-1,-1)]
START_LEN    = len(START_BITS)   # 32
END_LEN      = len(END_BITS)     # 24

FILE_MARKER  = b"-_-"
FILENAME_SEP = b":"

class ChannelState:
    def __init__(self):
        # sincronização com préâmbulo
        self.state = "idle"
        self.times = deque(maxlen=PREAMBLE_COUNT)
        self.slot = NOMINAL_SLOT
        self.tol  = NOMINAL_TOL
        self.t0: Optional[float] = None

        # decodificação por índice
        self.bits: List[int] = []
        self.idx_seen: Set[int] = set()
        self.max_idx_seen: int = -1
        self.last_idx_time: Optional[float] = None

        # framing
        self.start_pos: Optional[int] = None   # posição após "/"
        self.end_pos:   Optional[int] = None   # início de 0x01

        # medição
        self.msg_first_idx_time: Optional[float] = None

    def reset_for_next(self):
        self.__init__()

def clamp_slot(slot: float) -> float:
    # janela razoável ao redor de 50ms
    if 0.045 <= slot <= 0.055:
        return slot
    return NOMINAL_SLOT

def robust_preamble(d: List[float]):
    if len(d) != 5:
        return False, None, None
    mu_all = sum(d) / 5.0
    j = max(range(5), key=lambda i: abs(d[i]-mu_all))
    core = [x for i,x in enumerate(d) if i != j]
    mu = sum(core)/4.0
    sig = statistics.pstdev(core) if len(core) > 1 else 0.0
    k = max(1, round(mu / NOMINAL_SLOT))
    slot = clamp_slot(mu / k)
    tol  = max(NOMINAL_TOL, min(0.030, 3.0 * (sig / k)))  # tol proporcional; teto 30ms
    return True, slot, tol

def bits_to_bytes_msb_first(bits: List[int]) -> bytes:
    n = (len(bits)//8)*8
    bits = bits[:n]
    out = bytearray()
    for i in range(0, n, 8):
        v = 0
        for b in bits[i:i+8]:
            v = (v<<1) | (b & 1)
        out.append(v)
    return bytes(out)

class Decoder:
    def __init__(self, allowed_ips: set[str], require_sig: bool, sig: bytes, verbose: bool):
        self.allowed = allowed_ips
        self.require_sig = require_sig
        self.sig = sig
        self.verbose = verbose
        self.channels: Dict[str, ChannelState] = defaultdict(ChannelState)
        self.pk_seen: Dict[Tuple[str,int,int], float] = {}

    def payload_ok_and_index(self, pkt) -> Tuple[bool, Optional[int]]:
        if Raw in pkt:
            data = bytes(pkt[Raw].load)
        else:
            try:
                data = bytes(pkt[ICMP].payload)
            except Exception:
                data = b""
        if self.require_sig and not data.startswith(self.sig):
            return False, None

        base = len(self.sig)
        # Preferir 32 bits; fallback 16 bits (compat)
        if len(data) >= base + 4:
            idx = int.from_bytes(data[base:base+4], "big")
            return True, idx
        elif len(data) >= base + 2:
            idx = int.from_bytes(data[base:base+2], "big")
            return True, idx
        else:
            return True, None

    def accept_packet(self, src: str, icmp_id: int, icmp_seq: int, t: float) -> bool:
        key = (src, icmp_id, icmp_seq)
        last = self.pk_seen.get(key)
        if last and (t - last) < 1.0:
            return False
        self.pk_seen[key] = t
        now = time.time()
        if len(self.pk_seen) > 8000:
            self.pk_seen = {k:v for k,v in self.pk_seen.items() if now - v < PKT_CACHE_TTL}
        return True

    def on_ping(self, src: str, t: float, idx: Optional[int]):
        ch = self.channels[src]

        # 1) Préâmbulo para estimar slot e t0
        if ch.state == "idle":
            ch.times.append(t)
            if self.verbose:
                print(f"[DBG] ping de {src} @ {t:.6f} (idle)")
            if len(ch.times) == PREAMBLE_COUNT:
                d = [ch.times[i+1]-ch.times[i] for i in range(-PREAMBLE_COUNT, -1)]
                ok, slot, tol = robust_preamble(d)
                if ok:
                    ch.slot, ch.tol = slot, tol
                    ch.state = "sync"
                    ch.t0 = ch.times[-1] + ch.slot
                    if self.verbose:
                        print(f"[SYNC] tolerante {src}: slot={ch.slot:.3f} tol=±{ch.tol:.3f}")
                ch.times.popleft()
            return

        # 2) Em sync, só processa se houver índice
        if idx is None:
            return

        if ch.msg_first_idx_time is None:
            ch.msg_first_idx_time = t
            if self.verbose:
                print(f"[SYNC] indexado {src}: slot={ch.slot:.3f} tol=±{ch.tol:.3f} (idx0={idx})")

        if idx not in ch.idx_seen:
            ch.idx_seen.add(idx)
            if idx >= len(ch.bits):
                ch.bits.extend([0] * (idx - len(ch.bits) + 1))
            ch.bits[idx] = 1
            ch.max_idx_seen = max(ch.max_idx_seen, idx)
            ch.last_idx_time = t
            if self.verbose:
                print(f"[BIT-IDX] {src} -> 1 no slot #{idx}")

        # 3) Detecta início "!#-/"
        if ch.start_pos is None and len(ch.bits) >= START_LEN:
            pos = find_pattern(ch.bits, START_BITS)
            if pos is not None:
                ch.start_pos = pos + START_LEN
                if self.verbose:
                    print(f"[FIND-START] {src} start_pos={ch.start_pos}")

        # 4) Detecta terminador 01 05 07
        if ch.start_pos is not None and ch.end_pos is None:
            pos_end = find_pattern(ch.bits[ch.start_pos:], END_BITS)
            if pos_end is not None:
                ch.end_pos = ch.start_pos + pos_end
                if self.verbose:
                    print(f"[FIND-END] {src} end_pos={ch.end_pos}")

        # 5) Finalização
        if ch.end_pos is not None:
            end_bits_total = ch.end_pos + END_LEN
            saw_last = (ch.max_idx_seen >= end_bits_total - 1)
            quiet_ok = (ch.last_idx_time is not None and (t - ch.last_idx_time) >= 6 * ch.slot)
            if saw_last or quiet_ok:
                self.finish_message(src, ch)
        # Guard-rail: silêncio prolongado após START, sem END
        elif ch.start_pos is not None:
            quiet_ok = (ch.last_idx_time is not None and (t - ch.last_idx_time) >= 24 * ch.slot)
            if quiet_ok:
                pos_end = find_pattern(ch.bits[ch.start_pos:], END_BITS)
                if pos_end is not None:
                    ch.end_pos = ch.start_pos + pos_end
                    self.finish_message(src, ch)
                else:
                    if self.verbose:
                        print(f"[WARN] Silêncio longo após START mas sem END — descartando frame de {src}")
                    ch.reset_for_next()

    def finish_message(self, src: str, ch: ChannelState):
        if ch.start_pos is None or ch.end_pos is None:
            ch.reset_for_next()
            return

        # Bits do conteúdo entre START e o início do terminador
        msg_bits = ch.bits[ch.start_pos:ch.end_pos]
        data = bits_to_bytes_msb_first(msg_bits)

        # Duração estimada do payload completo (START + conteúdo + END)
        end_bits_total = ch.end_pos + END_LEN
        payload_bits_total = end_bits_total
        duration_data = payload_bits_total * ch.slot

        # Arquivo ou texto?
        if data.startswith(FILE_MARKER):
            rest = data[len(FILE_MARKER):]
            sep = rest.find(FILENAME_SEP)
            if sep > 0:
                fname_bytes = rest[:sep]
                blob = rest[sep+1:]
                fname = os.path.basename(fname_bytes.decode("utf-8", errors="replace")).strip()
                if not fname:
                    fname = "arquivo_recebido.bin"
                try:
                    with open(fname, "wb") as f:
                        f.write(blob)
                    bits_file = len(blob) * 8
                    eff_bps = bits_file / max(1e-6, duration_data)
                    print(f"[{time.strftime('%H:%M:%S')}] Arquivo de {src} salvo: {fname} "
                          f"({len(blob)} bytes) • duração≈{duration_data:.2f}s • taxa≈{eff_bps:.2f} bps")
                except Exception as e:
                    print(f"[ERRO] Falha ao salvar arquivo '{fname}': {e}")
            ch.reset_for_next()
            return

        # Mensagem de texto
        text = data.decode("utf-8", errors="replace")
        print(f"[{time.strftime('%H:%M:%S')}] Mensagem de {src}: {text}")
        ch.reset_for_next()

def find_pattern(bits: List[int], pat: List[int]) -> Optional[int]:
    n = len(bits); m = len(pat)
    if m == 0 or n < m:
        return None
    for i in range(0, n - m + 1):
        if bits[i:i+m] == pat:
            return i
    return None

def build_bpf(allowed_ips: List[str], dst_filter: Optional[str]) -> str:
    base = "icmp and icmp[icmptype] == icmp-echo"
    parts = [base]
    if allowed_ips:
        parts.append("(" + " or ".join(f"src host {ip}" for ip in allowed_ips) + ")")
    if dst_filter:
        parts.append(f"(dst host {dst_filter})")
    return " and ".join(parts)

def choose_iface(allowed: set[str], user_iface: Optional[str]) -> Optional[str]:
    if user_iface:
        return user_iface
    for ip in allowed:
        try:
            if ipaddress.ip_address(ip).is_loopback:
                return "lo"
        except ValueError:
            pass
    return None

def parse_args():
    ap = argparse.ArgumentParser(description="Servidor ICMP 50ms (assinatura+idx32), início '!#-/', fim 01 05 07, arquivo.")
    ap.add_argument("-a","--allow", action="append", required=True, help="IPs permitidos (repita ou use vírgulas)")
    ap.add_argument("-i","--iface", default=None, help="Interface (ex.: lo, wlan0)")
    ap.add_argument("--dst", default=None, help="Filtrar por IP de destino")
    ap.add_argument("--require-sig", action="store_true", help="Aceitar apenas pacotes com assinatura")
    ap.add_argument("--sig-hex", default=DEFAULT_SIG_HEX, help="Assinatura esperada (hex)")
    ap.add_argument("-v","--verbose", action="store_true")
    return ap.parse_args()

def main():
    args = parse_args()
    allowed = set(ip.strip() for item in args.allow for ip in item.split(",") if ip.strip())
    iface = choose_iface(allowed, args.iface)
    bpf = build_bpf(sorted(allowed), args.dst)
    sig_bytes = bytes.fromhex(args.sig_hex) if args.sig_hex else DEFAULT_SIG_BYTES
    dec = Decoder(allowed_ips=allowed, require_sig=args.require_sig, sig=sig_bytes, verbose=args.verbose)

    print(f"Escutando ICMP Echo de: {', '.join(sorted(allowed))}"
          f"{f' para dst {args.dst}' if args.dst else ''}"
          f"{f' na iface {iface!r}' if iface else ''}"
          f"{' [assinatura ' + args.sig_hex + ']' if args.require_sig else ''}"
          " … (pode exigir privilégios)")

    def handle(pkt):
        if IP in pkt and ICMP in pkt and int(pkt[ICMP].type) == 8:
            src = pkt[IP].src
            if src not in allowed:
                return
            icmp_id = int(getattr(pkt[ICMP], "id", -1))
            icmp_seq = int(getattr(pkt[ICMP], "seq", -1))
            t = pkt.time
            if not dec.accept_packet(src, icmp_id, icmp_seq, t):
                return
            ok, idx = dec.payload_ok_and_index(pkt)
            if not ok:
                return
            dec.on_ping(src, t, idx)

    try:
        sniffer = AsyncSniffer(filter=bpf, prn=handle, store=False, iface=iface, promisc=False)
        sniffer.start()
    except OSError as e:
        print(f"[WARN] Falha ao abrir iface {iface!r}: {e}. Tentando 'lo'…")
        sniffer = AsyncSniffer(filter=bpf, prn=handle, store=False, iface="lo", promisc=False)
        sniffer.start()

    try:
        while True:
            time.sleep(CHECK_INTERVAL)
    except KeyboardInterrupt:
        print("\nEncerrando…")
    finally:
        try: sniffer.stop()
        except Exception: pass

if __name__ == "__main__":
    main()
