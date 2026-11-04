package hardware

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

type GPU struct {
	Name      string `json:"name"`
	VRAMBytes uint64 `json:"vram_bytes"`
}

type Storage struct {
	Path           string `json:"path"`
	TotalBytes     uint64 `json:"total_bytes"`
	AvailableBytes uint64 `json:"available_bytes"`
}

type OllamaInventory struct {
	Available bool     `json:"available"`
	Models    []string `json:"models,omitempty"`
}

type Snapshot struct {
	OS           string          `json:"os"`
	Architecture string          `json:"architecture"`
	LogicalCPU   int             `json:"logical_cpu"`
	MemoryBytes  uint64          `json:"memory_bytes"`
	GPUs         []GPU           `json:"gpus,omitempty"`
	Storage      *Storage        `json:"storage,omitempty"`
	Ollama       OllamaInventory `json:"ollama"`
	Warnings     []string        `json:"warnings,omitempty"`
}

type ProfileName string

const (
	Light        ProfileName = "light"
	Standard     ProfileName = "standard"
	Performance  ProfileName = "performance"
	ServerCustom ProfileName = "server-custom"
)

type Profile struct {
	Name              ProfileName `json:"name"`
	MaxCPU            int         `json:"max_cpu"`
	MaxMemoryBytes    uint64      `json:"max_memory_bytes"`
	MaxGPU            int         `json:"max_gpu"`
	MaxVRAMBytes      uint64      `json:"max_vram_bytes"`
	ReserveCPU        int         `json:"reserve_cpu"`
	ReserveMemoryByte uint64      `json:"reserve_memory_bytes"`
}

func Recommend(s Snapshot) Profile {
	giB := uint64(1024 * 1024 * 1024)
	switch {
	case s.LogicalCPU >= 12 && s.MemoryBytes >= 24*giB:
		return profileFor(s, Performance)
	case s.LogicalCPU >= 6 && s.MemoryBytes >= 12*giB:
		return profileFor(s, Standard)
	default:
		reserveMemory := reserveMemoryFor(s.MemoryBytes, 2*giB)
		reserveCPU := min(1, max(0, s.LogicalCPU-1))
		return Profile{Name: Light, MaxCPU: max(1, s.LogicalCPU-reserveCPU), MaxMemoryBytes: s.MemoryBytes - reserveMemory, MaxGPU: 0, MaxVRAMBytes: 0, ReserveCPU: reserveCPU, ReserveMemoryByte: reserveMemory}
	}
}

func ValidateCustom(s Snapshot, p Profile) error {
	if p.Name != ServerCustom {
		return fmt.Errorf("custom profile name must be %q", ServerCustom)
	}
	if p.MaxCPU < 1 || p.MaxCPU+p.ReserveCPU > s.LogicalCPU {
		return fmt.Errorf("custom CPU budget exceeds detected capacity")
	}
	if p.MaxMemoryBytes == 0 || p.MaxMemoryBytes+p.ReserveMemoryByte > s.MemoryBytes {
		return fmt.Errorf("custom memory budget exceeds detected capacity")
	}
	if p.MaxGPU > len(s.GPUs) || p.MaxVRAMBytes > totalVRAM(s.GPUs) {
		return fmt.Errorf("custom GPU budget exceeds detected capacity")
	}
	return nil
}

// SelectProfile validates an explicit profile request. An empty name selects the recommendation.
func SelectProfile(s Snapshot, requested ProfileName, custom *Profile) (Profile, error) {
	if requested == "" {
		return Recommend(s), nil
	}
	if requested == ServerCustom {
		if custom == nil {
			return Profile{}, fmt.Errorf("server-custom profile requires operator values")
		}
		if err := ValidateCustom(s, *custom); err != nil {
			return Profile{}, err
		}
		return *custom, nil
	}
	if requested != Light && requested != Standard && requested != Performance {
		return Profile{}, fmt.Errorf("unknown profile %q", requested)
	}
	p := profileFor(s, requested)
	return p, nil
}

func profileFor(s Snapshot, name ProfileName) Profile {
	reserveCPU, reserveMemory := min(1, max(0, s.LogicalCPU-1)), reserveMemoryFor(s.MemoryBytes, 2*giB)
	maxCPU, maxMemory, maxGPU, maxVRAM := max(1, s.LogicalCPU-reserveCPU), s.MemoryBytes-reserveMemory, 0, uint64(0)
	if name == Standard {
		reserveCPU, reserveMemory = min(2, max(0, s.LogicalCPU-1)), reserveMemoryFor(s.MemoryBytes, 3*giB)
		maxCPU, maxMemory, maxGPU, maxVRAM = max(1, s.LogicalCPU-reserveCPU), s.MemoryBytes-reserveMemory, len(s.GPUs), totalVRAM(s.GPUs)
	}
	if name == Performance {
		reserveCPU, reserveMemory = min(2, max(0, s.LogicalCPU-1)), reserveMemoryFor(s.MemoryBytes, 4*giB)
		maxCPU, maxMemory, maxGPU, maxVRAM = max(1, s.LogicalCPU-reserveCPU), s.MemoryBytes-reserveMemory, len(s.GPUs), totalVRAM(s.GPUs)
	}
	return Profile{Name: name, MaxCPU: maxCPU, MaxMemoryBytes: maxMemory, MaxGPU: maxGPU, MaxVRAMBytes: maxVRAM, ReserveCPU: reserveCPU, ReserveMemoryByte: reserveMemory}
}

func Detect() Snapshot {
	s := Snapshot{OS: runtime.GOOS, Architecture: runtime.GOARCH, LogicalCPU: runtime.NumCPU()}
	if memory, err := detectMemory(); err == nil {
		s.MemoryBytes = memory
	} else {
		s.Warnings = append(s.Warnings, err.Error())
	}
	if gpus, err := detectNVIDIA(); err == nil {
		s.GPUs = gpus
	} else {
		s.Warnings = append(s.Warnings, err.Error())
	}
	if storage, err := detectStorage(); err == nil {
		s.Storage = &storage
	} else {
		s.Warnings = append(s.Warnings, fmt.Sprintf("storage inventory unavailable: %v", err))
	}
	if ollama, err := detectOllama(); err == nil {
		s.Ollama = ollama
	} else {
		s.Warnings = append(s.Warnings, fmt.Sprintf("Ollama inventory unavailable: %v", err))
	}
	return s
}

func detectOllama() (OllamaInventory, error) {
	path, err := exec.LookPath("ollama")
	if err != nil {
		return OllamaInventory{}, err
	}
	out, err := exec.Command(path, "list").Output()
	if err != nil {
		return OllamaInventory{}, err
	}
	return OllamaInventory{Available: true, Models: parseOllamaList(string(out))}, nil
}

func parseOllamaList(output string) []string {
	var models []string
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.EqualFold(fields[0], "name") {
			continue
		}
		models = append(models, fields[0])
	}
	return models
}

func detectMemory() (uint64, error) {
	switch runtime.GOOS {
	case "linux":
		file, err := os.Open("/proc/meminfo")
		if err != nil {
			return 0, err
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 2 && fields[0] == "MemTotal:" {
				value, err := strconv.ParseUint(fields[1], 10, 64)
				return value * 1024, err
			}
		}
		return 0, fmt.Errorf("MemTotal missing from /proc/meminfo")
	case "darwin":
		out, err := exec.Command("/usr/sbin/sysctl", "-n", "hw.memsize").Output()
		if err != nil {
			return 0, err
		}
		return strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
	case "windows":
		out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory").Output()
		if err != nil {
			return 0, err
		}
		return strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
	default:
		return 0, fmt.Errorf("memory detection is not implemented for %s", runtime.GOOS)
	}
}

func detectNVIDIA() ([]GPU, error) {
	out, err := exec.Command("nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader,nounits").Output()
	if err != nil {
		return nil, fmt.Errorf("NVIDIA inventory unavailable: %w", err)
	}
	var result []GPU
	for _, line := range bytes.Split(bytes.TrimSpace(out), []byte("\n")) {
		parts := strings.SplitN(string(line), ",", 2)
		if len(parts) != 2 {
			continue
		}
		mib, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 64)
		if err != nil {
			continue
		}
		result = append(result, GPU{Name: strings.TrimSpace(parts[0]), VRAMBytes: mib * 1024 * 1024})
	}
	return result, nil
}

func totalVRAM(gpus []GPU) uint64 {
	var total uint64
	for _, gpu := range gpus {
		total += gpu.VRAMBytes
	}
	return total
}

const giB = uint64(1024 * 1024 * 1024)

func reserveMemoryFor(capacity, desired uint64) uint64 {
	if capacity <= 1 {
		return 0
	}
	if desired >= capacity {
		return capacity / 2
	}
	return desired
}
