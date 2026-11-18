"""解析 pktcap.dll 生成的 .bin 抓包文件。

用法:
    python pktdump.py <文件> [--hex] [--filter 关键字] [--max N]
"""
import sys, os, struct, datetime

HDR = b"PKTCAP01"

def parse(path):
    with open(path, "rb") as f:
        data = f.read()
    if data[:8] != HDR:
        raise SystemExit("不是 pktcap 文件（缺少 PKTCAP01 头）")
    i = 12
    recs = []
    while i + 19 <= len(data):
        direction = chr(data[i])
        ln, ts, ip, port = struct.unpack_from("<IQIH", data, i + 1)
        payload = data[i + 19:i + 19 + ln]
        if len(payload) < ln:
            break
        recs.append((direction, ts, ip, port, payload))
        i += 19 + ln
    return recs

def ipstr(ip):
    return "%d.%d.%d.%d" % ((ip >> 24) & 255, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255)

def main():
    if len(sys.argv) < 2:
        print(__doc__); return
    path = sys.argv[1]
    show_hex = "--hex" in sys.argv
    flt = None
    if "--filter" in sys.argv:
        flt = sys.argv[sys.argv.index("--filter") + 1]
    limit = None
    if "--max" in sys.argv:
        limit = int(sys.argv[sys.argv.index("--max") + 1])

    recs = parse(path)
    t0 = recs[0][1] if recs else 0
    print(f"文件: {os.path.basename(path)}  记录数: {len(recs)}  总字节: {sum(len(r[4]) for r in recs)}")
    print(f"{'#':>6} {'t(ms)':>9} {'dir':>3} {'len':>5}  对端                预览")
    print("-" * 100)

    n = 0
    for idx, (d, ts, ip, port, payload) in enumerate(recs):
        text = payload.decode("latin-1")
        if flt and flt.lower() not in text.lower() and flt not in payload.hex():
            continue
        preview = "".join(chr(b) if 32 <= b < 127 else "." for b in payload[:48])
        print(f"{idx:>6} {ts - t0:>9} {d:>3} {len(payload):>5}  {ipstr(ip) + ':' + str(port):<20} {preview}")
        if show_hex:
            for off in range(0, min(len(payload), 128), 16):
                chunk = payload[off:off + 16]
                print("        %04X  %-47s  %s" % (
                    off, " ".join("%02X" % b for b in chunk),
                    "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)))
        n += 1
        if limit and n >= limit:
            break
    print(f"\n显示 {n} 条")

if __name__ == "__main__":
    main()
