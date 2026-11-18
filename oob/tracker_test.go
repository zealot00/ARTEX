package oob

import (
	"fmt"
	"strings"
	"testing"
)

func TestTrackerLifecycle(t *testing.T) {
	tr := NewTracker()

	tok, err := tr.CreateToken(42, "ssrf-check")
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if len(tok.ID) != 24 {
		t.Fatalf("unexpected token length %d", len(tok.ID))
	}

	if ok := tr.RecordHit("missing-token", Hit{Method: "GET"}); ok {
		t.Fatal("expected RecordHit to reject unknown token")
	}

	longBody := strings.Repeat("A", maxBodyPreview+500)
	if ok := tr.RecordHit(tok.ID, Hit{
		RemoteIP: "10.0.0.15",
		Method:   "POST",
		Path:     "/oob/" + tok.ID + "/cb",
		Body:     longBody,
	}); !ok {
		t.Fatal("expected RecordHit to succeed")
	}

	if _, _, ok := tr.PollHits(99, tok.ID); ok {
		t.Fatal("expected PollHits to enforce task isolation")
	}

	gotTok, hits, ok := tr.PollHits(42, tok.ID)
	if !ok {
		t.Fatal("expected PollHits to find token")
	}
	if gotTok.HitCount != 1 || len(hits) != 1 {
		t.Fatalf("got hitCount=%d len(hits)=%d, want 1", gotTok.HitCount, len(hits))
	}
	if !strings.HasSuffix(hits[0].Body, "...(truncated)") {
		t.Fatalf("expected truncated body preview, got len=%d", len(hits[0].Body))
	}

	tr.DeleteTask(42)
	if _, _, ok := tr.PollHits(42, tok.ID); ok {
		t.Fatal("expected DeleteTask to clear token")
	}
}

func TestTrackerBounds(t *testing.T) {
	tr := NewTracker()
	var firstID string
	for i := 0; i < maxTokensPerTask+5; i++ {
		tok, err := tr.CreateToken(7, fmt.Sprintf("t-%d", i))
		if err != nil {
			t.Fatalf("CreateToken(%d): %v", i, err)
		}
		if i == 0 {
			firstID = tok.ID
		}
	}
	if _, _, ok := tr.PollHits(7, firstID); ok {
		t.Fatal("expected oldest token to be evicted past maxTokensPerTask")
	}
	if got := len(tr.ListTaskTokens(7)); got != maxTokensPerTask {
		t.Fatalf("ListTaskTokens len=%d, want %d", got, maxTokensPerTask)
	}
}
