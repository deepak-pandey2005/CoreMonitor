package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/deepak-pandey2005/CoreMonitor/pkg/cbridge"
	"github.com/deepak-pandey2005/CoreMonitor/pkg/config"
	"github.com/deepak-pandey2005/CoreMonitor/pkg/engine"
	"github.com/deepak-pandey2005/CoreMonitor/pkg/geoip"
	"github.com/deepak-pandey2005/CoreMonitor/pkg/tui"
)

func printUsage() {
	fmt.Println("Usage: coremonitor [command] [options]")
	fmt.Println("\nCommands:")
	fmt.Println("  live     Capture live network traffic from an interface")
	fmt.Println("  pcap     Inspect and analyze an offline .pcap file")
	fmt.Println("\nRun 'coremonitor [command] -h' for command options.")
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]

	switch cmd {
	case "live":
		runLive(os.Args[2:])
	case "pcap":
		runPCAP(os.Args[2:])
	case "-h", "--help", "help":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func runLive(args []string) {
	fs := flag.NewFlagSet("live", flag.ExitOnError)
	ifaceFlag := fs.String("i", "", "Network interface (default from config, e.g. wlan0)")
	bpfFlag := fs.String("b", "", "BPF filter string")
	cfgFlag := fs.String("c", "config.yaml", "Path to config file")
	noTUIFlag := fs.Bool("no-tui", false, "Disable live terminal dashboard")
	noInfluxFlag := fs.Bool("no-influx", false, "Disable InfluxDB metrics export")
	_ = fs.Parse(args)

	cfg, err := config.LoadConfig(*cfgFlag)
	if err != nil {
		fmt.Printf("[Warning] Could not load %s, using defaults: %v\n", *cfgFlag, err)
	}

	if *ifaceFlag != "" {
		cfg.Network.Interface = *ifaceFlag
	}
	if *bpfFlag != "" {
		cfg.Network.BPFFilter = *bpfFlag
	}
	if *noInfluxFlag {
		cfg.InfluxDB.Enabled = false
	}
	if *noTUIFlag {
		cfg.LiveDashboard = false
	}

	capHandle, err := cbridge.OpenLive(cfg.Network.Interface, cfg.Network.BPFFilter, cfg.Network.Promiscuous, cfg.Network.Snaplen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintf(os.Stderr, "Hint: Run with sudo or set capabilities with scripts/setup_permissions.sh\n")
		os.Exit(1)
	}

	eng, err := engine.NewEngine(*cfg, capHandle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize monitor engine: %v\n", err)
		os.Exit(1)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nStopping CoreMonitor gracefully...")
		eng.Stop()
		os.Exit(0)
	}()

	go func() {
		if err := eng.ProcessLoop(); err != nil {
			fmt.Fprintf(os.Stderr, "Capture loop error: %v\n", err)
		}
	}()

	if cfg.LiveDashboard {
		if err := tui.RunBubbleTea(eng, cfg.Network.Interface); err != nil {
			fmt.Fprintf(os.Stderr, "TUI error: %v\n", err)
		}
	} else {
		fmt.Printf("CoreMonitor live engine running on %s. Press Ctrl+C to stop.\n", cfg.Network.Interface)
		select {}
	}
}

func runPCAP(args []string) {
	fs := flag.NewFlagSet("pcap", flag.ExitOnError)
	cfgFlag := fs.String("c", "config.yaml", "Path to config file")
	noInfluxFlag := fs.Bool("no-influx", false, "Disable InfluxDB metrics export")
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Println("Usage: coremonitor pcap [options] <pcap-file>")
		os.Exit(1)
	}
	pcapFile := fs.Arg(0)

	cfg, _ := config.LoadConfig(*cfgFlag)
	if *noInfluxFlag {
		cfg.InfluxDB.Enabled = false
	}

	capHandle, err := cbridge.OpenOffline(pcapFile, cfg.Network.BPFFilter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening PCAP: %v\n", err)
		os.Exit(1)
	}

	eng, err := engine.NewEngine(*cfg, capHandle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Engine init error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Analyzing PCAP file: %s ...\n", pcapFile)
	startTime := time.Now()
	_ = eng.ProcessLoop()
	elapsed := time.Since(startTime)
	eng.Stop()

	stats := eng.GetStats()
	fmt.Printf("\n✓ PCAP Analysis Completed in %v\n", elapsed)
	fmt.Printf("Total Packets: %d\n", stats.TotalPackets)
	fmt.Printf("Total Volume:  %.2f KB\n", float64(stats.TotalBytes)/1024)
	fmt.Printf("Alerts Found:  %d\n\n", len(stats.RecentAlerts))

	if len(stats.RecentAlerts) > 0 {
		fmt.Println("🚨 Security Alerts Detected:")
		for _, a := range stats.RecentAlerts {
			src := a.SrcIP
			if a.SrcFlag != "" {
				src = fmt.Sprintf("%s %s", a.SrcFlag, a.SrcIP)
			}
			dst := a.DstIP
			if a.DstFlag != "" {
				dst = fmt.Sprintf("%s %s", a.DstFlag, a.DstIP)
			}
			fmt.Printf("  • [%s] %s (%s -> %s): %s\n", a.Severity, a.AlertType, src, dst, a.Message)
		}
	}

	if len(stats.BannedHosts) > 0 {
		fmt.Printf("\n🛡️ Active Defense (IPS) Jailed %d Host(s) (Mode: %s):\n", len(stats.BannedHosts), cfg.IPS.Mode)
		for _, h := range stats.BannedHosts {
			loc := geoip.Lookup(h.IP)
			fmt.Printf("  • [%s] %s %-15s | %s\n", h.Severity, loc.Flag, h.IP, h.Reason)
		}
	}
}

