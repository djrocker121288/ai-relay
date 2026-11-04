package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAdmissionReserveAndFullDemand(t *testing.T) {
	s, err := New(Resources{CPU: 8, MemoryByte: 16, GPU: 1, VRAMByte: 8}, Resources{CPU: 2, MemoryByte: 4})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Acquire(Request{ID: "a", Project: "p", Resources: Resources{CPU: 7, MemoryByte: 12}}); !errors.Is(err, ErrInsufficientCapacity) {
		t.Fatalf("expected reserve enforcement, got %v", err)
	}
	if err := s.SetFullDemand(true, false); err == nil {
		t.Fatal("unauthorized full-demand accepted")
	}
	if err := s.SetFullDemand(true, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Acquire(Request{ID: "a", Project: "p", Resources: Resources{CPU: 7, MemoryByte: 12}}); err != nil {
		t.Fatal(err)
	}
}

func TestReclamationIsCooperativeAndDeterministic(t *testing.T) {
	s, _ := New(Resources{CPU: 8, MemoryByte: 16}, Resources{})
	a, _ := s.Acquire(Request{ID: "low", Project: "a", Priority: 1, Reclaimable: true, Resources: Resources{CPU: 3, MemoryByte: 4}})
	_, _ = s.Acquire(Request{ID: "fixed", Project: "b", Priority: 9, Reclaimable: false, Resources: Resources{CPU: 3, MemoryByte: 4}})
	plan, ok := s.ReclamationPlan(Resources{CPU: 4, MemoryByte: 8}, 5)
	if !ok || len(plan) != 1 || plan[0].ID != a.ID {
		t.Fatalf("unexpected plan: %#v, %v", plan, ok)
	}
	if s.Available().CPU != 2 {
		t.Fatal("planning mutated live allocations")
	}
}

func TestProjectQuotaAndReleaseUsage(t *testing.T) {
	s, err := New(Resources{CPU: 8, MemoryByte: 16}, Resources{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetProjectQuota("p", ProjectQuota{Resources: Resources{CPU: 3, MemoryByte: 8}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Acquire(Request{ID: "one", Project: "p", Resources: Resources{CPU: 2, MemoryByte: 4}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Acquire(Request{ID: "two", Project: "p", Resources: Resources{CPU: 2}}); !errors.Is(err, ErrProjectQuota) {
		t.Fatalf("expected quota rejection, got %v", err)
	}
	if !s.Release("one") {
		t.Fatal("release failed")
	}
	if _, err := s.Acquire(Request{ID: "two", Project: "p", Resources: Resources{CPU: 2}}); err != nil {
		t.Fatalf("released usage was not reclaimed: %v", err)
	}
}

func TestQueuedAdmissionIsFairAcrossProjects(t *testing.T) {
	s, _ := New(Resources{CPU: 1}, Resources{})
	if _, err := s.Acquire(Request{ID: "holder", Project: "holder", Resources: Resources{CPU: 1}}); err != nil {
		t.Fatal(err)
	}
	results := make(chan string, 2)
	for _, request := range []Request{
		{ID: "a", Project: "a", Resources: Resources{CPU: 1}},
		{ID: "b", Project: "b", Resources: Resources{CPU: 1}},
	} {
		request := request
		go func() {
			allocation, err := s.AcquireQueued(context.Background(), request)
			if err != nil {
				t.Errorf("queued acquire: %v", err)
				return
			}
			results <- allocation.ID
		}()
	}
	time.Sleep(20 * time.Millisecond)
	if !s.Release("holder") {
		t.Fatal("holder release failed")
	}
	first := <-results
	if first != "a" && first != "b" {
		t.Fatalf("unexpected first allocation %q", first)
	}
	if !s.Release(first) {
		t.Fatal("first queued release failed")
	}
	second := <-results
	if second == first {
		t.Fatalf("same project was admitted twice before other project: %q", second)
	}
}

func TestQueuedCancellationDoesNotConsumeCapacity(t *testing.T) {
	s, _ := New(Resources{CPU: 1}, Resources{})
	_, _ = s.Acquire(Request{ID: "holder", Project: "p", Resources: Resources{CPU: 1}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := s.AcquireQueued(ctx, Request{ID: "cancelled", Project: "q", Resources: Resources{CPU: 1}})
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	if !s.Release("holder") {
		t.Fatal("holder release failed")
	}
	if _, err := s.Acquire(Request{ID: "after", Project: "p", Resources: Resources{CPU: 1}}); err != nil {
		t.Fatalf("cancelled waiter consumed capacity: %v", err)
	}
}

func TestQueuedQuotaWaitsForProjectRelease(t *testing.T) {
	s, _ := New(Resources{CPU: 2}, Resources{})
	if err := s.SetProjectQuota("p", ProjectQuota{Resources: Resources{CPU: 1}}); err != nil {
		t.Fatal(err)
	}
	_, _ = s.Acquire(Request{ID: "holder", Project: "p", Resources: Resources{CPU: 1}})
	done := make(chan error, 1)
	go func() {
		_, err := s.AcquireQueued(context.Background(), Request{ID: "waiter", Project: "p", Resources: Resources{CPU: 1}})
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if !s.Release("holder") {
		t.Fatal("holder release failed")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("queued quota admission failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("queued quota admission was not dispatched after release")
	}
}

func TestSmallerSameProjectRequestBypassesBlockedLargeRequest(t *testing.T) {
	s, _ := New(Resources{CPU: 2}, Resources{})
	_, _ = s.Acquire(Request{ID: "holder", Project: "holder", Resources: Resources{CPU: 1}})
	largeCtx, cancelLarge := context.WithCancel(context.Background())
	defer cancelLarge()
	largeDone := make(chan error, 1)
	go func() {
		_, err := s.AcquireQueued(largeCtx, Request{ID: "large", Project: "p", Priority: 10, Resources: Resources{CPU: 2}})
		largeDone <- err
	}()
	time.Sleep(20 * time.Millisecond)
	smallDone := make(chan error, 1)
	go func() {
		_, err := s.AcquireQueued(context.Background(), Request{ID: "small", Project: "p", Priority: 1, Resources: Resources{CPU: 1}})
		smallDone <- err
	}()
	select {
	case err := <-smallDone:
		if err != nil {
			t.Fatalf("smaller request failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("smaller request was blocked behind a request that could not fit")
	}
	cancelLarge()
	if err := <-largeDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected large request cancellation, got %v", err)
	}
}

func TestFullDemandExpansionDispatchesQueue(t *testing.T) {
	s, _ := New(Resources{CPU: 2}, Resources{CPU: 1})
	_, _ = s.Acquire(Request{ID: "holder", Project: "p", Resources: Resources{CPU: 1}})
	done := make(chan error, 1)
	go func() {
		_, err := s.AcquireQueued(context.Background(), Request{ID: "waiter", Project: "q", Resources: Resources{CPU: 1}})
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if err := s.SetFullDemand(true, true); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("full-demand dispatch failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("full-demand capacity expansion did not dispatch queued work")
	}
}

func TestNegativeResourcesRejected(t *testing.T) {
	if _, err := New(Resources{CPU: -1}, Resources{}); err == nil {
		t.Fatal("negative capacity accepted")
	}
	s, _ := New(Resources{CPU: 2}, Resources{})
	if _, err := s.Acquire(Request{ID: "bad", Project: "p", Resources: Resources{CPU: -1}}); err == nil {
		t.Fatal("negative request accepted")
	}
	if err := s.SetProjectQuota("p", ProjectQuota{Resources: Resources{GPU: -1}}); err == nil {
		t.Fatal("negative quota accepted")
	}
}

func TestImpossibleQueuedRequestAndQueuedDuplicateRejected(t *testing.T) {
	s, _ := New(Resources{CPU: 1}, Resources{})
	if _, err := s.AcquireQueued(context.Background(), Request{ID: "impossible", Project: "p", Resources: Resources{CPU: 2}}); !errors.Is(err, ErrInsufficientCapacity) {
		t.Fatalf("expected permanent capacity rejection, got %v", err)
	}
	_, _ = s.Acquire(Request{ID: "holder", Project: "p", Resources: Resources{CPU: 1}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := s.AcquireQueued(ctx, Request{ID: "duplicate", Project: "q", Resources: Resources{CPU: 1}})
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if _, err := s.Acquire(Request{ID: "duplicate", Project: "q", Resources: Resources{}}); err == nil {
		t.Fatal("immediate acquire duplicated a queued request ID")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func TestPressureIsReadOnlyAndTruthful(t *testing.T) {
	s, _ := New(Resources{CPU: 4, MemoryByte: 100}, Resources{})
	_, _ = s.Acquire(Request{ID: "reclaim", Project: "p", Reclaimable: true, Resources: Resources{CPU: 3, MemoryByte: 80}})
	pressure := s.Pressure()
	if pressure.Level != PressureConstrained || pressure.Reclaimable != 1 || pressure.Available.CPU != 1 {
		t.Fatalf("unexpected pressure: %#v", pressure)
	}
	if !s.Release("reclaim") || s.Available().CPU != 4 {
		t.Fatal("pressure observation changed allocation state")
	}
}
