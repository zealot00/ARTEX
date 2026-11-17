package intercept

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRedirectCheckEnforcesElectronicFence(t *testing.T) {
	var outsideHits atomic.Int32
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outsideHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(outside.Close)

	inside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, outside.URL+"/secret", http.StatusFound)
	}))
	t.Cleanup(inside.Close)

	ctx := WithTargetScope(t.Context(), TargetScope{
		TaskID: "99",
		FenceCheck: func(rawURL string) error {
			if strings.HasPrefix(rawURL, inside.URL) {
				return nil
			}
			return fmt.Errorf("electronic fence: %s is outside scope", rawURL)
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, inside.URL+"/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{CheckRedirect: RedirectCheck("WebFetch")}
	_, err = client.Do(req)
	if err == nil || !strings.Contains(err.Error(), "electronic fence") {
		t.Fatalf("expected electronic fence error on redirect, got: %v", err)
	}
	if outsideHits.Load() != 0 {
		t.Fatalf("outside server was hit %d times across redirect", outsideHits.Load())
	}
}
