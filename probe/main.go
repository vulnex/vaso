package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
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

	if err := writeSnapshot(os.Stdout, &snapshot); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding snapshot: %v\n", err)
		os.Exit(1)
	}
}

// writeSnapshot encodes the snapshot as indented JSON, names that are not
// UTF-8 written without loss (fs_names.go).
func writeSnapshot(w io.Writer, snapshot *ProbeSnapshot) error {
	token := newEscapeToken()
	escaped := escapeSnapshotNames(snapshot, token)
	if !escaped {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(snapshot)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(snapshot); err != nil {
		return err
	}
	_, err := w.Write(restoreEscapes(buf.Bytes(), token))
	return err
}
