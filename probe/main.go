package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

var version = "dev"

func main() {
	manifestPath := flag.String("manifest", "", "Path to manifest JSON file")
	escalate := flag.Bool("escalate", false, "Attempt sudo escalation for full scan")
	showVersion := flag.Bool("version", false, "Show version")
	flag.Parse()

	if *showVersion {
		fmt.Fprintf(os.Stderr, "vaso-probe %s\n", version)
		os.Exit(0)
	}

	var manifest ProbeManifest
	if *manifestPath != "" {
		data, err := os.ReadFile(*manifestPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading manifest: %v\n", err)
			os.Exit(1)
		}
		if err := json.Unmarshal(data, &manifest); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing manifest: %v\n", err)
			os.Exit(1)
		}
	} else {
		manifest = DefaultManifest()
	}

	snapshot := Collect(manifest, *escalate)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(snapshot); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding snapshot: %v\n", err)
		os.Exit(1)
	}
}
