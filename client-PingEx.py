#!/usr/bin/env python3
import time, platform, subprocess, sys, argparse, os
from typing import List, Tuple

# ===== Especificação do canal =====
PULSE_S = 0.050               # 50 ms por slot (maior bitrate)
PREAMBLE_LEN = 6              # 6 pings para pré-sincronismo

# Assinatura fixa (8 bytes) "STG!STG!"
SIG_HEX   = "5354472153544721"
SIG_BYTES = bytes.fromhex(SIG_HEX)
SIG_LEN   = 8                 # payload do ping p/ preâmbulo
DATA_LEN  = 12                # assinatura(8) + índice(4)

# ===== Protocolo =====
START_BYTES  = b"!#-/"                     # início fixo
END_BYTES    = bytes([0x01, 0x05, 0x07])   # terminador
FILE_MARKER  = b"-_-"
FILENAME_SEP = b":"

def sys_is_linux():   return platform.system().lower() == "linux"
def sys_is_macos():   return platform.system().lower() == "darwin"
def sys_is_windows(): return platform.system().lower() == "windows"

def bytes_to_bits_msb_first(b: bytes) -> List[int]:
    bits = []
    for byte in b:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits

def build_ping_cmd_once(ip: str, size: int, pattern_hex: str | None) -> List[str]:
    if sys_is_windows():
        return ["ping", "-n", "1", "-w", "100", ip]
    elif sys_is_macos():
        cmd = ["ping", "-c", "1", "-W", "100", "-s", str(size)]
        if pattern_hex: cmd += ["-p", pattern_hex]
        return cmd + [ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", "-s", str(size)]
        if pattern_hex: cmd += ["-p", pattern_hex]
        return cmd + [ip]

def fire_ping(ip: str, size: int, pattern_hex: str | None, verbose: bool, label: str) -> Tuple[float, float]:
    cmd = build_ping_cmd_once(ip, size, pattern_hex)
    t_epoch = time.time()
    t_perf  = time.perf_counter()
    try:
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        print("[ERRO] 'ping' não encontrado no PATH."); sys.exit(1)
    if verbose:
        print(f"[SEND] {label} epoch={t_epoch:.6f} perf={t_perf:.6f} cmd={' '.join(cmd)}")
    return t_epoch, t_perf

def send_preamble(ip: str, force_sched: bool, use_sig: bool, verbose: bool) -> Tuple[float, float]:
    """
    Envia 6 pings espaçados de PULSE_S.
    Retorna (perf_do_primeiro_pre, perf_do_último_pre).
    """
    pattern = SIG_HEX if use_sig and not sys_is_windows() else None

    # aquecimento
    fire_ping(ip, SIG_LEN if pattern else 8, pattern, verbose, "warmup")
    time.sleep(0.02)

    # Se o slot for < 0.2s, evitamos -i por limitação do ping sem root
    can_single_proc = (PULSE_S >= 0.2) and (sys_is_linux() or sys_is_macos()) and not sys_is_windows()
    if not force_sched and can_single_proc:
        cmd = ["ping", "-c", str(PREAMBLE_LEN), "-i", f"{PULSE_S:.3f}"] + \
              (["-W","1"] if sys_is_linux() else ["-W","100"])
        if use_sig: cmd += ["-s", str(SIG_LEN), "-p", SIG_HEX]
        cmd += [ip]
        if verbose: print(f"[PRE] single-proc: {' '.join(cmd)}")
        t0 = time.perf_counter()
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            # timeout proporcional
            p.wait(timeout=PREAMBLE_LEN * (PULSE_S + 0.2) + 1.0)
        except Exception:
            try: p.terminate()
            except Exception: pass
        t_first = t0
        t_last  = t0 + (PREAMBLE_LEN - 1) * PULSE_S
        return t_first, t_last

    # Préâmbulo cronometrado
    base = time.perf_counter()
    if verbose: print(f"[PRE] scheduled base(perf)={base:.6f}")
    t_first = None
    t_last  = None
    for i in range(PREAMBLE_LEN):
        _, perf = fire_ping(ip, SIG_LEN if pattern else 8, pattern, verbose, f"pre[{i}]")
        if t_first is None: t_first = perf
        t_last = perf
        t_next = base + (i + 1) * PULSE_S
        while True:
            dt = t_next - time.perf_counter()
            if dt <= 0: break
            time.sleep(min(dt, 0.002))   # passos menores (50ms exige granularidade melhor)
    return t_first, t_last

def send_bits_stream(ip: str, bits: List[int], use_sig: bool, verbose: bool, is_file: bool):
    label_suffix = "(file)" if is_file else ""
    # Préâmbulo
    pre_first_perf, last_pre_perf = send_preamble(ip, force_sched=True if PULSE_S < 0.2 else False,
                                                  use_sig=use_sig, verbose=verbose)
    base = last_pre_perf + PULSE_S
    if verbose:
        print(f"[BASE] base(perf)={base:.6f} total_bits={len(bits)} {label_suffix}")

    # Medição
    t_start_total = pre_first_perf
    t_start_data  = base

    for idx, bit in enumerate(bits):
        t_slot = base + idx * PULSE_S
        while True:
            dt = t_slot - time.perf_counter()
            if dt <= 0: break
            time.sleep(min(dt, 0.002))
        if bit == 1:
            if use_sig and not sys_is_windows():
                # índice 32-bit big-endian
                pat = SIG_HEX + f"{idx & 0xFFFFFFFF:08x}"
                fire_ping(ip, DATA_LEN, pat, verbose, f"bit[{idx}]=1 {label_suffix}".strip())
            else:
                fire_ping(ip, 8, None, verbose, f"bit[{idx}]=1 {label_suffix}".strip())
        else:
            if verbose:
                print(f"[SLOT] i={idx} bit=0 {label_suffix}".strip())

    t_end = time.perf_counter()
    return t_start_total, t_start_data, t_end

def send_message(ip: str, text: str, use_sig: bool, verbose: bool):
    payload = START_BYTES + text.encode("utf-8") + END_BYTES
    bits = bytes_to_bits_msb_first(payload)
    t0, t_data0, t1 = send_bits_stream(ip, bits, use_sig, verbose, is_file=False)
    elapsed_total = max(1e-6, t1 - t0)
    print(f"[INFO] Mensagem enviada em {elapsed_total:.2f}s")

def send_file(ip: str, path: str, use_sig: bool, verbose: bool):
    fname = os.path.basename(path).encode("utf-8", errors="ignore")
    with open(path, "rb") as f:
        blob = f.read()

    payload = START_BYTES + FILE_MARKER + fname + FILENAME_SEP + blob + END_BYTES
    bits = bytes_to_bits_msb_first(payload)

    # Estatística e estimativa
    bits_file     = len(blob) * 8
    bits_payload  = len(bits)
    bits_overhead = bits_payload - bits_file
    eta_data_s    = bits_payload * PULSE_S
    eta_total_s   = PREAMBLE_LEN * PULSE_S + eta_data_s
    theo_bps      = 1.0 / PULSE_S

    print(f"[INFO] Envio de arquivo: {os.path.basename(path)} "
          f"({len(blob)} bytes) • dados={bits_file} bits • overhead={bits_overhead} bits "
          f"• total_payload={bits_payload} bits • taxa_teórica≈{theo_bps:.2f} bps "
          f"• ETA_dados≈{eta_data_s:.2f}s • ETA_total≈{eta_total_s:.2f}s")

    t0, t_data0, t1 = send_bits_stream(ip, bits, use_sig, verbose, is_file=True)
    elapsed_total = max(1e-6, t1 - t0)
    elapsed_data  = max(1e-6, t1 - t_data0)
    bps_payload_total = bits_payload / elapsed_total
    bps_file_total    = bits_file / elapsed_total

    print(f"[INFO] Arquivo enviado em {elapsed_total:.2f}s "
          f"(dados≈{elapsed_data:.2f}s) • throughput_total(payload)≈{bps_payload_total:.2f} bps "
          f"• throughput_total(arquivo)≈{bps_file_total:.2f} bps")

def main():
    ap = argparse.ArgumentParser(description="Cliente ICMP (50 ms) com assinatura + índice32 + texto/arquivo.")
    ap.add_argument("ip")
    ap.add_argument("--sched-preamble", action="store_true",
                    help="Força préâmbulo cronometrado (sempre usado se slot<0.2s).")
    ap.add_argument("--no-sig", action="store_true",
                    help="Desliga assinatura/índice (use servidor sem --require-sig).")
    ap.add_argument("--file", help="Caminho do arquivo para enviar (modo arquivo).")
    ap.add_argument("-v","--verbose", action="store_true")
    args = ap.parse_args()

    use_sig = not args.no_sig

    if args.file:
        send_file(args.ip, args.file, use_sig, args.verbose)

    print("Digite a mensagem e ENTER para enviar. Linha vazia encerra.")
    while True:
        try:
            msg = input("> ")
        except EOFError:
            break
        if not msg:
            break
        send_message(args.ip, msg, use_sig, args.verbose)
        print("Mensagem enviada.")

if __name__ == "__main__":
    main()
