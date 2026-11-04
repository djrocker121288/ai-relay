package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ai-relay/ai-relay/internal/v2/hardware"
)

func main() {
	requested := flag.String("profile", "", "profile to validate/select: light, standard, performance, or server-custom")
	customPath := flag.String("custom-profile", "", "JSON profile file required with -profile server-custom")
	flag.Parse()
	snapshot := hardware.Detect()
	var custom *hardware.Profile
	if hardware.ProfileName(*requested) == hardware.ServerCustom {
		if *customPath == "" {
			fmt.Fprintln(os.Stderr, "-custom-profile is required with -profile server-custom")
			os.Exit(2)
		}
		file, err := os.Open(*customPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		profile, err := decodeCustomProfile(file)
		_ = file.Close()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		custom = &profile
	}
	selected, err := hardware.SelectProfile(snapshot, hardware.ProfileName(*requested), custom)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	result := struct {
		Hardware hardware.Snapshot `json:"hardware"`
		Profile  hardware.Profile  `json:"selected_profile"`
	}{Hardware: snapshot, Profile: selected}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func decodeCustomProfile(reader io.Reader) (hardware.Profile, error) {
	data, err := io.ReadAll(io.LimitReader(reader, (64<<10)+1))
	if err != nil {
		return hardware.Profile{}, err
	}
	if len(data) > 64<<10 {
		return hardware.Profile{}, fmt.Errorf("custom profile exceeds 64 KiB")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var profile hardware.Profile
	if err := decoder.Decode(&profile); err != nil {
		return profile, fmt.Errorf("decode custom profile: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return profile, fmt.Errorf("custom profile must contain one JSON object")
	}
	if profile.Name != hardware.ServerCustom {
		return profile, fmt.Errorf("custom profile name must be %q", hardware.ServerCustom)
	}
	return profile, nil
}
