# CoreMonitor 🛡️

A high-performance Network Traffic Analyzer and Intrusion Detection System (IDS).

## Architecture

- **Core Engine (C)**: High-speed packet capture using `libpcap`, zero-copy packet parser, and stateful IDS detection engine.
- **Upper Layer (Go)**: Modern orchestration layer connecting to the C core via CGO for real-time visualization, storage management (PCAP/CSV), and InfluxDB/Grafana metrics.
- **Tooling & Simulation (Python / uv)**: Traffic generator for testing and simulating security events.
