#!/usr/bin/env python3
"""간단한 파이썬 TCP 포트 스캐너 (nmap의 쉬운 버전)

사용 예:
  python3 scanner.py                                  # 대화형으로 host/ports 입력
  python3 scanner.py --host 127.0.0.1 --ports 1-100 --mode sequential
  python3 scanner.py --host 127.0.0.1 --ports 1-1000  # 기본: 스레드 모드
  python3 scanner.py --host 127.0.0.1 --ports 1-1000 --compare  # 순차 vs 스레드 속도 비교

주의: 반드시 본인 소유이거나 허가받은 호스트(127.0.0.1, scanme.nmap.org 등)에만 사용할 것.
"""

import argparse
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# socket.getservbyport가 실패할 때를 대비한 보충용 서비스 이름 테이블
COMMON_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "domain", 80: "http", 110: "pop3", 143: "imap", 443: "https",
    445: "microsoft-ds", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    6379: "redis", 8080: "http-proxy", 27017: "mongodb",
}


def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except OSError:
        return COMMON_SERVICES.get(port, "unknown")


def scan_port(host, port, timeout=1.0):
    """포트 하나를 TCP connect_ex로 확인. (port, open 여부) 반환."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        # connect_ex는 예외를 던지는 대신 에러 코드를 반환한다 (0 == 성공 == OPEN)
        result = sock.connect_ex((host, port))
        return port, result == 0


def sequential_scan(host, ports, timeout=1.0, verbose=True):
    """Level 1: 포트를 하나씩 순서대로 스캔."""
    open_ports = []
    for port in ports:
        _, is_open = scan_port(host, port, timeout)
        if verbose:
            print(f"Port {port}: {'OPEN' if is_open else 'CLOSED'}")
        if is_open:
            open_ports.append(port)
    return open_ports


def threaded_scan(host, ports, timeout=1.0, max_workers=50, verbose=True):
    """Level 2: ThreadPoolExecutor로 여러 포트를 동시에 스캔."""
    open_ports = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, host, p, timeout): p for p in ports}
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)

    open_ports.sort()
    if verbose:
        for port in open_ports:
            service = get_service_name(port)
            print(f"Port {port} ({service}) : OPEN")
    return open_ports


def parse_port_range(port_str):
    port_str = port_str.strip()
    if "-" in port_str:
        start, end = port_str.split("-", 1)
        return list(range(int(start), int(end) + 1))
    return [int(port_str)]


def build_arg_parser():
    parser = argparse.ArgumentParser(description="간단한 파이썬 TCP 포트 스캐너")
    parser.add_argument("--host", help="스캔할 대상 IP 또는 도메인")
    parser.add_argument("--ports", help="포트 범위 (예: 1-1000) 또는 단일 포트")
    parser.add_argument("--threads", type=int, default=50, help="스레드 모드에서 사용할 워커 수 (기본 50)")
    parser.add_argument("--timeout", type=float, default=1.0, help="소켓 타임아웃(초) (기본 1.0)")
    parser.add_argument("--mode", choices=["sequential", "threaded"], default="threaded",
                         help="스캔 방식 선택 (기본 threaded)")
    parser.add_argument("--compare", action="store_true",
                         help="순차/스레드 스캔을 둘 다 실행해서 소요 시간을 비교 출력")
    return parser


def main():
    args = build_arg_parser().parse_args()

    host = args.host or input("Target host (IP or domain): ").strip() or "127.0.0.1"
    port_str = args.ports or input("Port range (e.g. 1-100): ").strip() or "1-100"
    ports = parse_port_range(port_str)

    print(f"Target: {host}")

    if args.compare:
        print(f"\n[Sequential] Scanning ports {port_str}...")
        t0 = time.time()
        seq_open = sequential_scan(host, ports, args.timeout, verbose=False)
        seq_elapsed = time.time() - t0
        print(f"Sequential scan finished in {seq_elapsed:.2f}s (open: {len(seq_open)})")

        print(f"\n[Threaded] Scanning ports {port_str} with {args.threads} threads...")
        t0 = time.time()
        thr_open = threaded_scan(host, ports, args.timeout, args.threads, verbose=False)
        thr_elapsed = time.time() - t0
        print(f"Threaded scan finished in {thr_elapsed:.2f}s (open: {len(thr_open)})")

        if thr_elapsed > 0:
            print(f"\n=> Speedup: {seq_elapsed / thr_elapsed:.1f}x faster with threads")
        return

    if args.mode == "sequential":
        print(f"Scanning ports {port_str}...")
        t0 = time.time()
        open_ports = sequential_scan(host, ports, args.timeout)
        elapsed = time.time() - t0
        print(f"\nScan complete. {len(open_ports)} open port(s) found. ({elapsed:.2f}s)")
    else:
        print(f"Scanning {host} (ports {port_str}) with {args.threads} threads...")
        t0 = time.time()
        open_ports = threaded_scan(host, ports, args.timeout, args.threads)
        elapsed = time.time() - t0
        closed = len(ports) - len(open_ports)
        print(f"Scan finished in {elapsed:.2f}s (open: {len(open_ports)}, closed: {closed})")


if __name__ == "__main__":
    main()
