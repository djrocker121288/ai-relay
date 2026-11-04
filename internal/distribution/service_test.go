package distribution

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestUpdateRejectsPathTraversalSegments(t *testing.T) {
	d := t.TempDir()
	if err := os.WriteFile(filepath.Join(filepath.Dir(d), "amd64.json"), []byte(`{"unexpected":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	s := &Service{ManifestDir: d}
	r := httptest.NewRequest(http.MethodGet, "/v1/updates/../amd64", nil)
	w := httptest.NewRecorder()
	s.update(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
	}
}

func TestUpdateServesSafeManifestPath(t *testing.T) {
	d := t.TempDir()
	if err := os.WriteFile(filepath.Join(d, "linux-amd64.json"), []byte(`{"version":"1.0.0"}`), 0600); err != nil {
		t.Fatal(err)
	}
	s := &Service{ManifestDir: d}
	r := httptest.NewRequest(http.MethodGet, "/v1/updates/linux/amd64", nil)
	w := httptest.NewRecorder()
	s.update(w, r)
	if w.Code != http.StatusOK || w.Body.String() != `{"version":"1.0.0"}` {
		t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
	}
}
