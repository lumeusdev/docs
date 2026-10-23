// Minimal Lumeus webhook receiver. Go 1.22+, standard library only.
//
//	WEBHOOK_SECRET=whsec_... go run .
//	WEBHOOK_SECRET_FILE=webhook-secret.txt go run .
//
// The secret comes from WEBHOOK_SECRET, or from the file named by
// WEBHOOK_SECRET_FILE, which is read on every request: you can start the
// receiver before you create the subscription, and it answers 503 until the
// file exists. During a signing-key rotation also set WEBHOOK_NEXT_SECRET.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxBody          = 256 << 10 // deliveries are at most 64 KiB
	toleranceSeconds = 300
)

var signature = regexp.MustCompile(`^t=([0-9]{1,12}),v1=([a-fA-F0-9]{64})$`)

// Context is the signed delivery context (X-Webhook-Delivery-Context).
type Context struct {
	Domain         string `json:"domain"`
	DeliveryID     int64  `json:"delivery_id"`
	SubscriptionID string `json:"subscription_id"`
	EventID        string `json:"event_id"`
	Lane           string `json:"lane"`
	ReplayJobID    string `json:"replay_job_id"`
	Network        string `json:"network"`
	Generation     string `json:"generation"`
	BodySHA256     string `json:"body_sha256"`
}

// Event holds the fields this receiver uses; deliveries carry more.
type Event struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Type    string `json:"type"`
	Network string `json:"network"`
	Ledger  int64  `json:"ledger"`
}

// check returns the signed timestamp if one secret signed payload.
func check(header string, payload []byte, secrets []string, now time.Time) string {
	m := signature.FindStringSubmatch(header)
	if m == nil {
		return ""
	}
	ts, _ := strconv.ParseInt(m[1], 10, 64)
	if math.Abs(float64(now.Unix()-ts)) > toleranceSeconds {
		return ""
	}
	received, _ := hex.DecodeString(m[2])
	for _, secret := range secrets {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(m[1] + "."))
		mac.Write(payload)
		if hmac.Equal(mac.Sum(nil), received) {
			return m[1]
		}
	}
	return ""
}

// Verify checks the body signature, timestamp and signed delivery context.
// Error messages are short codes that are safe to log.
func Verify(body []byte, h http.Header, secrets []string, now time.Time) (Context, Event, error) {
	var ctx Context
	var ev Event
	ts := check(h.Get("X-Webhook-Signature"), body, secrets, now)
	if ts == "" {
		ts = check(h.Get("X-Webhook-Next-Signature"), body, secrets, now)
	}
	if ts == "" {
		return ctx, ev, errors.New("invalid_webhook_signature")
	}
	encoded := h.Get("X-Webhook-Delivery-Context")
	if encoded == "" {
		return ctx, ev, errors.New("missing_delivery_context")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(encoded) > 16384 {
		return ctx, ev, errors.New("invalid_delivery_context")
	}
	cts := check(h.Get("X-Webhook-Context-Signature"), raw, secrets, now)
	if cts == "" {
		cts = check(h.Get("X-Webhook-Next-Context-Signature"), raw, secrets, now)
	}
	if cts != ts {
		return ctx, ev, errors.New("invalid_context_signature")
	}
	if json.Unmarshal(raw, &ctx) != nil || json.Unmarshal(body, &ev) != nil {
		return ctx, ev, errors.New("context_body_mismatch")
	}
	network := func(n string) string {
		if n == "pubnet" {
			return "mainnet"
		}
		return n
	}
	digest := sha256.Sum256(body)
	lane := ctx.Lane == "live" || ctx.Lane == "replay" && ctx.ReplayJobID != "" ||
		ctx.Lane == "test" && ev.Kind == "test" && h.Get("X-Webhook-Test") == "true"
	if ctx.Domain != "lumeus-delivery-context-v1" || ctx.Generation == "" || ctx.SubscriptionID == "" ||
		ctx.EventID != ev.ID || network(ctx.Network) != network(ev.Network) ||
		ctx.BodySHA256 != hex.EncodeToString(digest[:]) || !lane {
		return ctx, ev, errors.New("context_body_mismatch")
	}
	return ctx, ev, nil
}

// currentSecrets reads the secrets from the environment and the secret file.
func currentSecrets(secretFile string) []string {
	var secrets []string
	for _, name := range []string{"WEBHOOK_SECRET", "WEBHOOK_NEXT_SECRET"} {
		if v := os.Getenv(name); v != "" {
			secrets = append(secrets, v)
		}
	}
	if secretFile != "" {
		if b, err := os.ReadFile(secretFile); err == nil { // missing until the subscription exists
			if v := strings.TrimSpace(string(b)); v != "" {
				secrets = append(secrets, v)
			}
		}
	}
	return secrets
}

func main() {
	secretFile := os.Getenv("WEBHOOK_SECRET_FILE")
	if os.Getenv("WEBHOOK_SECRET") == "" && secretFile == "" {
		log.Fatal("set WEBHOOK_SECRET or WEBHOOK_SECRET_FILE")
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	var mu sync.Mutex
	seen := map[string]bool{} // demo only: in production use a database UNIQUE key on (network, event id)

	http.HandleFunc("POST /", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		secrets := currentSecrets(secretFile)
		if len(secrets) == 0 {
			log.Println("no secret yet: waiting for", secretFile)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		ctx, ev, err := Verify(body, r.Header, secrets, time.Now())
		if err != nil {
			log.Println("rejected:", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		key := ctx.Network + "|" + ev.ID
		mu.Lock()
		duplicate := seen[key]
		if ctx.Lane != "test" {
			seen[key] = true // store the event and enqueue your work here, before you answer
		}
		mu.Unlock()
		switch {
		case ctx.Lane == "test":
			log.Println("verified test delivery", ev.ID)
		case duplicate:
			log.Println("duplicate, already processed", ev.ID)
		default:
			log.Printf("verified %s %s %s %s ledger %d", ctx.Lane, ev.Kind, ev.Type, ev.ID, ev.Ledger)
		}
		w.WriteHeader(http.StatusNoContent) // answer fast with an empty body
	})
	log.Printf("listening on http://localhost:%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
