"""Rich terminal user interface (TUI) for real-time monitoring."""

import time
from datetime import datetime
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from coremonitor.capture import LiveStats
from coremonitor.models import AlertSeverity


def create_header(interface: str, start_time: float) -> Panel:
    elapsed = int(time.time() - start_time)
    mins, secs = divmod(elapsed, 60)
    hours, mins = divmod(mins, 60)
    uptime = f"{hours:02d}:{mins:02d}:{secs:02d}"

    grid = Table.grid(expand=True)
    grid.add_column(justify="left", ratio=1)
    grid.add_column(justify="center", ratio=2)
    grid.add_column(justify="right", ratio=1)

    grid.add_row(
        f"[bold cyan]Interface:[/] [yellow]{interface}[/]",
        "[bold green]🛡️ CoreMonitor Network Traffic Analyzer & IDS[/]",
        f"[bold cyan]Uptime:[/] [white]{uptime}[/]",
    )
    return Panel(grid, style="blue")


def create_stats_panel(stats: LiveStats) -> Panel:
    with stats.lock:
        total_pkts = stats.total_packets
        total_mb = stats.total_bytes / (1024 * 1024)
        rate_kbs = stats.bytes_per_sec / 1024
        rate_pps = stats.pkts_per_sec

    table = Table(box=None, expand=True)
    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Value", style="bold white")

    table.add_row("Total Packets Captured", f"{total_pkts:,}")
    table.add_row("Total Data Volume", f"{total_mb:.2f} MB")
    table.add_row("Current Throughput", f"{rate_kbs:.2f} KB/s")
    table.add_row("Packet Rate", f"{rate_pps:.1f} pkts/sec")

    return Panel(table, title="[bold]Bandwidth & Flow[/]", border_style="cyan")


def create_protocols_panel(stats: LiveStats) -> Panel:
    with stats.lock:
        protocols = stats.protocol_counts.most_common(5)
        total = stats.total_packets or 1

    table = Table(box=None, expand=True)
    table.add_column("Protocol", style="magenta")
    table.add_column("Packets", justify="right")
    table.add_column("Share", justify="right", style="green")

    for proto, count in protocols:
        pct = (count / total) * 100
        table.add_row(proto, f"{count:,}", f"{pct:.1f}%")

    if not protocols:
        table.add_row("Waiting for traffic...", "-", "-")

    return Panel(table, title="[bold]Protocols[/]", border_style="magenta")


def create_talkers_panel(stats: LiveStats) -> Panel:
    with stats.lock:
        talkers = stats.top_talkers_bytes.most_common(5)

    table = Table(box=None, expand=True)
    table.add_column("Host IP", style="yellow")
    table.add_column("Volume", justify="right", style="bold green")

    for ip, bytes_count in talkers:
        if bytes_count > 1024 * 1024:
            vol = f"{bytes_count / (1024 * 1024):.2f} MB"
        else:
            vol = f"{bytes_count / 1024:.1f} KB"
        table.add_row(ip, vol)

    if not talkers:
        table.add_row("Waiting for traffic...", "-")

    return Panel(table, title="[bold]Top Talkers[/]", border_style="yellow")


def create_alerts_table(stats: LiveStats) -> Panel:
    with stats.lock:
        alerts = list(stats.recent_alerts)[-6:]

    table = Table(expand=True, box=None)
    table.add_column("Time", style="dim", width=10)
    table.add_column("Severity", width=10)
    table.add_column("Alert Type", style="bold", width=22)
    table.add_column("Source -> Target", width=34)
    table.add_column("Details", style="white")

    sev_styles = {
        AlertSeverity.CRITICAL: "[bold white on red] CRITICAL [/]",
        AlertSeverity.HIGH: "[bold red] HIGH [/]",
        AlertSeverity.MEDIUM: "[yellow] MEDIUM [/]",
        AlertSeverity.LOW: "[blue] LOW [/]",
    }

    for alert in reversed(alerts):
        sev_badge = sev_styles.get(alert.severity, str(alert.severity))
        t_str = alert.timestamp.strftime("%H:%M:%S")
        src_dst = f"{alert.src_ip or '*'} -> {alert.dst_ip or '*'}"
        table.add_row(t_str, sev_badge, alert.alert_type, src_dst, alert.message)

    if not alerts:
        table.add_row("", "[green]CLEAN[/]", "NO THREATS DETECTED", "-", "Network traffic within baseline thresholds.")

    return Panel(table, title="[bold red]🚨 Live IDS Security Alerts[/]", border_style="red")


def create_packets_table(stats: LiveStats) -> Panel:
    with stats.lock:
        packets = list(stats.recent_packets)[-6:]

    table = Table(expand=True, box=None)
    table.add_column("Time", style="dim", width=10)
    table.add_column("Source", width=22)
    table.add_column("Destination", width=22)
    table.add_column("Proto", width=7, style="magenta")
    table.add_column("Service", width=14, style="cyan")
    table.add_column("Size", justify="right", width=8)
    table.add_column("Flags / Info", style="white")

    for pkt in reversed(packets):
        t_str = pkt.timestamp.strftime("%H:%M:%S")
        src = f"{pkt.src_ip}:{pkt.src_port}" if pkt.src_port else pkt.src_ip
        dst = f"{pkt.dst_ip}:{pkt.dst_port}" if pkt.dst_port else pkt.dst_ip
        info = ",".join(pkt.tcp_flags) if pkt.tcp_flags else (pkt.dns_query or "")
        table.add_row(t_str, src, dst, pkt.protocol, pkt.service or "-", f"{pkt.packet_size}B", info)

    if not packets:
        table.add_row("", "Listening...", "", "", "", "", "")

    return Panel(table, title="[bold]Recent Packets[/]", border_style="white")


def generate_layout(interface: str, stats: LiveStats) -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="metrics", size=8),
        Layout(name="alerts", size=9),
        Layout(name="packets", size=9),
    )

    layout["header"].update(create_header(interface, stats.start_time))

    layout["metrics"].split_row(
        Layout(create_stats_panel(stats), ratio=1),
        Layout(create_protocols_panel(stats), ratio=1),
        Layout(create_talkers_panel(stats), ratio=1),
    )

    layout["alerts"].update(create_alerts_table(stats))
    layout["packets"].update(create_packets_table(stats))

    return layout
