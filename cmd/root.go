/*
Copyright © 2023 Michael Wagner <mitch.wagna@gmail.com>
*/
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	nmap "github.com/Ullaakut/nmap/v3"
	"github.com/spf13/cobra"
)

var (
	defaultHTTPBindAddress = "0.0.0.0"
	defaultHTTPBindPort    = "8080"
)

func init() {
	rootCmd.PersistentFlags().String("http.bind-address", defaultHTTPBindAddress, "defines the address to bind on")
	rootCmd.PersistentFlags().String("http.port", defaultHTTPBindPort, "defines the port to bind on")
	rootCmd.PersistentFlags().StringArray("scan.targets", []string{}, "defines the scan targets to monitor")
	rootCmd.PersistentFlags().StringArray("scan.ignored-ips", []string{}, "set host ips to ignore")
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "prom-http-sd",
	Short: "A HTTP server which exposes all node-exporters in the network",
	Long: `A HTTP server which allows to expose all node-exporters found in the given network to be exposed as Prometheus
scrape targets. This is  accomplished by using nmap scans for the specified port (default 9100).
In addition the hostname gets exported as labels.`,
	Run: func(cmd *cobra.Command, args []string) {
		bindAddress, err := cmd.Flags().GetString("http.bind-address")
		if err != nil {
			log.Fatalf("Error getting bind address from flag: %v", err)
		}
		bindPort, err := cmd.Flags().GetString("http.port")
		if err != nil {
			log.Fatalf("Error getting bind port from flag: %v", err)
		}
		listenAddr := net.JoinHostPort(bindAddress, bindPort)
		scanTargets, err := cmd.Flags().GetStringArray("scan.targets")
		if err != nil {
			log.Fatalf("Error getting scan targets from flag: %v", err)
		}
		if len(scanTargets) == 0 {
			log.Fatalln("No scan targets provided")
		}
		ignoredIPs, err := cmd.Flags().GetStringArray("scan.ignored-ips")
		if err != nil {
			log.Printf("Error getting ignored ips for the scan from flag: %v", err)
		}
		ignoredIPsMap := make(map[string]struct{})
		for _, ip := range ignoredIPs {
			ignoredIPsMap[ip] = struct{}{}
		}
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			results, err := nmapScan(r.Context(), ignoredIPsMap, scanTargets...)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if err != nil {
				log.Printf("Error scanning for machines: %v", err)
				fmt.Fprintln(w, "[]")
				return
			}
			if err := json.NewEncoder(w).Encode(results); err != nil {
				log.Printf("Error encoding results: %v", err)
				fmt.Fprintln(w, "[]")
				return
			}
		})
		log.Printf("Starting http service discovery at %s", listenAddr)
		log.Printf("Scanning targets: %v (ignoring %v)", scanTargets, ignoredIPs)
		log.Fatal(http.ListenAndServe(listenAddr, nil))
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}

}

type ScrapeConfig struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels"`
}

func nmapScan(ctx context.Context, ignoredIPs map[string]struct{}, scanTargets ...string) ([]ScrapeConfig, error) {
	log.Printf("Starting scan for targets %s", scanTargets)
	start := time.Now()
	var ignored int
	options := []nmap.Option{
		nmap.WithTargets(scanTargets...),
		nmap.WithTimingTemplate(nmap.TimingFastest),
		nmap.WithFilterHost(func(h nmap.Host) bool {
			for _, addr := range h.Addresses {
				if _, ok := ignoredIPs[addr.Addr]; ok {
					ignored++
					return false
				}
			}
			return true
		}),
		nmap.WithOpenOnly(),
		nmap.WithFilterPort(func(p nmap.Port) bool {
			return p.Protocol == "tcp"
		}),
	}
	if os.Getuid() == 0 {
		log.Println("scanning with OS detection enabled")
		options = append(options, nmap.WithOSDetection())
	}
	s, err := nmap.NewScanner(
		ctx,
		options...,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create nmap scanner: %w", err)
	}
	// Executes asynchronously, allowing results to be streamed in real time.
	done := make(chan error)
	result, warnings, err := s.Async(done).Run()
	if err != nil {
		log.Println(warnings)
		return nil, fmt.Errorf("error performning scan: %w", err)
	}

	// Blocks main until the scan has completed.
	if err := <-done; err != nil {
		if len(*warnings) > 0 {
			log.Printf("run finished with warnings: %s\n", *warnings) // Warnings are non-critical errors from nmap.
		}
		return nil, fmt.Errorf("error finishing scan: %w", err)
	}
	configs := []ScrapeConfig{}
	for _, host := range result.Hosts {
		if len(host.Hostnames) == 0 {
			continue
		}
		var ipv4Addr string
		var macAddr string
		var macAddrVendor string
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" {
				ipv4Addr = addr.Addr
			}
			if addr.AddrType == "mac" {
				macAddr = addr.Addr
				macAddrVendor = addr.Vendor
			}
		}
		if ipv4Addr == "" {
			continue
		}
		labels := map[string]string{
			"host": host.Hostnames[0].Name,
		}
		if macAddr != "" {
			labels["mac_address"] = macAddr
		}
		if macAddrVendor != "" {
			labels["mac_address_vendor"] = macAddrVendor
		}
		if len(host.OS.Matches) > 0 {
			labels["guessed_os"] = host.OS.Matches[0].Name
			labels["guessed_os_accuracy"] = strconv.Itoa(host.OS.Matches[0].Accuracy)
		}
		configs = append(configs, ScrapeConfig{
			Targets: []string{ipv4Addr},
			Labels:  labels,
		})

	}
	log.Printf("Scan done, found %d hosts in %v (%d ignored)", len(configs), time.Since(start), ignored)
	return configs, nil
}
