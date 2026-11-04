package agentcore

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRun(t *testing.T) {
	c := New()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, e := c.Run(ctx, "x", "echo", []string{"hello"}, ".", nil, false)
	if e != nil || r["stdout"] != "hello\n" {
		t.Fatalf("run: %#v %v", r, e)
	}
}

func TestRunPreservesSeparateStandardError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix shell fixture")
	}
	result, err := New().Run(context.Background(), "streams", "sh", []string{"-c", "printf out; printf err >&2"}, ".", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if result["stdout"] != "out" || result["stderr"] != "err" || result["stdout_truncated"] != false || result["stderr_truncated"] != false {
		t.Fatalf("streams were not preserved: %#v", result)
	}
}
func TestCapabilities(t *testing.T) {
	if len(New().Capabilities()) < 5 {
		t.Fatal("capabilities missing")
	}
}

func TestNoUnimplementedCapabilities(t *testing.T) {
	for _, capability := range New().Capabilities() {
		switch capability {
		case "exec", "jobs", "jobs.cancel", "jobs.stdin", "files":
		default:
			t.Fatalf("unimplemented capability advertised: %s", capability)
		}
	}
}

func TestCancellationStopsShellChildren(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows child process containment requires native helper")
	}
	core := New()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	job, err := core.Start(ctx, "tree", "sh", []string{"-c", "sleep 30 & wait"}, ".", nil)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, got := range core.Jobs() {
			if got.ID == job.ID && got.Finished {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("shell child kept stdout pipe alive after cancellation")
}

func TestOutputTailAndTruncation(t *testing.T) {
	var writer tailWriter
	prefix := strings.Repeat("a", MaxOutputBytes)
	if n, err := writer.Write([]byte(prefix)); err != nil || n != len(prefix) {
		t.Fatal("output write failed")
	}
	writer.Write([]byte("tail"))
	if len(writer.data) != MaxOutputBytes || !strings.HasSuffix(writer.data, "tail") || !writer.truncated {
		t.Fatal("output tail or flag incorrect")
	}
}
func TestFinishedCachePreservesActiveAndDirectSnapshots(t *testing.T) {
	core := New()
	active := &Job{ID: "active"}
	core.jobs[active.ID] = active
	oldest := &Job{ID: "oldest", Finished: true, Started: time.Unix(1, 0), Stdout: "result"}
	core.jobs[oldest.ID] = oldest
	for i := 0; i < MaxFinishedJobs; i++ {
		id := fmt.Sprint(i)
		core.jobs[id] = &Job{ID: id, Finished: true, Started: time.Unix(int64(i+2), 0)}
	}
	core.pruneFinished()
	if len(core.jobs) != MaxFinishedJobs+1 || core.jobs["active"] == nil || core.jobs["oldest"] != nil {
		t.Fatal("completed retention cap incorrect")
	}
	if oldest.Snapshot().Stdout != "result" {
		t.Fatal("cache eviction lost pending direct result snapshot")
	}
}

func TestRunCapsActualProcessOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix shell fixture")
	}
	result, err := New().Run(context.Background(), "large", "sh", []string{"-c", "head -c 1200000 /dev/zero; printf tail"}, ".", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := result["stdout"].(string)
	if len(out) != MaxOutputBytes || !strings.HasSuffix(out, "tail") || result["stdout_truncated"] != true {
		t.Fatal("real process output was not capped truthfully")
	}
}
