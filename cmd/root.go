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
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.prom-http-sd.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	rootCmd.PersistentFlags().String("http.bind-address", defaultHTTPBindAddress, "defines the address to bind on")
	rootCmd.PersistentFlags().String("http.port", defaultHTTPBindPort, "defines the port to bind on")
	rootCmd.PersistentFlags().StringArray("scan.targets", []string{}, "defines the scan targets to monitor")
	rootCmd.PersistentFlags().String("scan.port", "9100", "defines the port to scan for")
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
		scanPort, err := cmd.Flags().GetString("scan.port")
		if err != nil {
			log.Fatalf("Error getting scan port from flag: %v", err)
		}
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			results, err := nmapScan(r.Context(), scanPort, scanTargets...)
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
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
		log.Printf("Scanning port %s on targets: %v", scanPort, scanTargets)
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

func nmapScan(ctx context.Context, scanPort string, scanTargets ...string) ([]ScrapeConfig, error) {
	log.Printf("Starting scan for targets %s", scanTargets)
	start := time.Now()
	s, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(scanTargets...),
		nmap.WithOpenOnly(),
		nmap.WithTimingTemplate(nmap.TimingFastest),
		nmap.WithPorts(scanPort),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	// Executes asynchronously, allowing results to be streamed in real time.
	done := make(chan error)
	result, warnings, err := s.Async(done).Run()
	if err != nil {
		log.Fatal(err)
	}

	// Blocks main until the scan has completed.
	if err := <-done; err != nil {
		if len(*warnings) > 0 {
			log.Printf("run finished with warnings: %s\n", *warnings) // Warnings are non-critical errors from nmap.
		}
		log.Fatal(err)
	}
	var configs []ScrapeConfig
	// Use the results to print an example output
	for _, host := range result.Hosts {
		for _, port := range host.Ports {
			configs = append(configs, ScrapeConfig{
				Targets: []string{net.JoinHostPort(host.Addresses[0].Addr, strconv.Itoa(int(port.ID)))},
				Labels: map[string]string{
					"app":  "node-exporter",
					"type": "external",
					"host": host.Hostnames[0].Name,
				},
			})
		}
	}
	log.Printf("Scan done, found %d hosts in %v", len(configs), time.Since(start))
	return configs, nil
}
