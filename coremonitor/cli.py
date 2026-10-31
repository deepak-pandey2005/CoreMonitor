"""Command-line interface for CoreMonitor."""

import argparse
import os
import signal
import sys
import time
from rich.console import Console
from rich.live import Live

from coremonitor.capture import TrafficMonitor
from coremonitor.config import AppConfig
from coremonitor.tui import generate_layout

console = Console()


def run_live(args: argparse.Namespace) -> None:
    config = AppConfig.load_from_yaml(args.config)

    if args.interface:
        config.network.interface = args.interface
    if args.bpf:
        config.network.bpf_filter = args.bpf
    if args.no_influx:
        config.influxdb.enabled = False

    monitor = TrafficMonitor(config)

    def sig_handler(sig, frame):
        console.print("\n[yellow]Shutting down CoreMonitor gracefully...[/]")
        monitor.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    try:
        monitor.start_live_capture()
    except PermissionError:
        console.print(
            "[bold red]Permission Denied:[/] Live packet sniffing requires root privileges or CAP_NET_RAW / CAP_NET_ADMIN capabilities."
        )
        console.print(
            "[yellow]Hint:[/] Run with [bold]sudo .venv/bin/python -m coremonitor live[/] or inspect an offline PCAP with [bold]python -m coremonitor pcap <file>[/]"
        )
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Failed to start capture on {config.network.interface}:[/] {e}")
        sys.exit(1)

    if args.no_tui or not config.live_dashboard:
        console.print(
            f"[bold green]CoreMonitor is running in background on {config.network.interface}. Press Ctrl+C to stop.[/]"
        )
        while monitor.is_running:
            time.sleep(1)
    else:
        with Live(
            generate_layout(config.network.interface, monitor.stats),
            refresh_per_second=2,
            screen=True,
        ) as live:
            while monitor.is_running:
                time.sleep(0.5)
                live.update(generate_layout(config.network.interface, monitor.stats))


def run_pcap(args: argparse.Namespace) -> None:
    if not os.path.exists(args.pcap_file):
        console.print(f"[bold red]File not found:[/] {args.pcap_file}")
        sys.exit(1)

    config = AppConfig.load_from_yaml(args.config)
    if args.no_influx:
        config.influxdb.enabled = False

    monitor = TrafficMonitor(config)

    def sig_handler(sig, frame):
        monitor.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)

    console.print(f"[bold cyan]Analyzing PCAP:[/] [white]{args.pcap_file}[/]")
    start_time = time.time()
    monitor.process_pcap_file(args.pcap_file)
    elapsed = time.time() - start_time

    # Print summary
    stats = monitor.stats
    console.print(f"\n[bold green]✓ PCAP Analysis Complete in {elapsed:.2f}s[/]")
    console.print(f"Total Packets: [bold cyan]{stats.total_packets:,}[/]")
    console.print(f"Total Volume:  [bold cyan]{stats.total_bytes / 1024:.2f} KB[/]")
    console.print(f"Alerts Found:  [bold red]{len(stats.recent_alerts)}[/]")

    if stats.recent_alerts:
        console.print("\n[bold red]Security Alerts Detected:[/]")
        for alert in stats.recent_alerts:
            console.print(
                f"  • [[bold]{alert.severity.value}[/]] [yellow]{alert.alert_type}[/] ({alert.src_ip} -> {alert.dst_ip}): {alert.message}"
            )


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="coremonitor",
        description="CoreMonitor - Network Traffic Analyzer and Intrusion Detection System",
    )
    parser.add_argument(
        "--config",
        "-c",
        default="config.yaml",
        help="Path to YAML configuration file (default: config.yaml)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Live capture command
    live_parser = subparsers.add_parser("live", help="Capture live network traffic from an interface")
    live_parser.add_argument(
        "-i",
        "--interface",
        help="Network interface name (e.g. wlan0, eth0, any)",
    )
    live_parser.add_argument(
        "-b",
        "--bpf",
        help="BPF filter string (e.g. 'tcp and port not 22')",
    )
    live_parser.add_argument(
        "--no-tui",
        action="store_true",
        help="Disable interactive terminal dashboard (plain logging)",
    )
    live_parser.add_argument(
        "--no-influx",
        action="store_true",
        help="Disable InfluxDB metrics export",
    )
    live_parser.set_defaults(func=run_live)

    # PCAP offline inspection command
    pcap_parser = subparsers.add_parser("pcap", help="Parse and analyze an offline .pcap file")
    pcap_parser.add_argument("pcap_file", help="Path to .pcap or .pcapng file")
    pcap_parser.add_argument(
        "--no-influx",
        action="store_true",
        help="Disable InfluxDB metrics export",
    )
    pcap_parser.set_defaults(func=run_pcap)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

