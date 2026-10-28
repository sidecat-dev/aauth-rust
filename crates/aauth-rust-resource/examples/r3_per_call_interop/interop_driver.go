package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

type driverConfig struct {
	APAddr         string `json:"ap_addr"`
	APCertPEM      string `json:"ap_cert_pem"`
	PSAddr         string `json:"ps_addr"`
	PSCertPEM      string `json:"ps_cert_pem"`
	RecordsAddr    string `json:"records_addr"`
	RecordsCertPEM string `json:"records_cert_pem"`
	InteropAddr    string `json:"interop_addr"`
	InteropCertPEM string `json:"interop_cert_pem"`
	AgentSeedHex   string `json:"agent_seed_hex"`
	AgentToken     string `json:"agent_token"`
	InitialNow     int64  `json:"initial_now"`
}

type interopState struct {
	Now          int64    `json:"now"`
	Reads        int      `json:"reads"`
	Deletes      []string `json:"deletes"`
	QueryRuns    int      `json:"query_runs"`
	AuditRecords int      `json:"audit_records"`
	Consents     []string `json:"consents"`
}

type converseRequest struct {
	GoAPAddr       string `json:"go_ap_addr"`
	GoAPCertHex    string `json:"go_ap_cert_hex"`
	GoPSAddr       string `json:"go_ps_addr"`
	GoPSCertHex    string `json:"go_ps_cert_hex"`
	GoAgentSeedHex string `json:"go_agent_seed_hex"`
	GoAgentToken   string `json:"go_agent_token"`
}

type converseResponse struct {
	PersonStatus          int    `json:"person_status"`
	ClassExchangeStatus   int    `json:"class_exchange_status"`
	ClassReadStatus       int    `json:"class_read_status"`
	UngrantedDeleteStatus int    `json:"ungranted_delete_status"`
	ProposalStatus        int    `json:"proposal_status"`
	ProposalError         string `json:"proposal_error"`
}

type transcriptOutput struct {
	GoToRustPersonTokenIssued                    bool     `json:"go_to_rust_person_token_issued"`
	GoToRustClassReadStatus                      int      `json:"go_to_rust_class_read_status"`
	GoToRust401ChallengeStatus                   int      `json:"go_to_rust_401_challenge_status"`
	GoToRustApprovalExpiryError                  string   `json:"go_to_rust_approval_expiry_error"`
	GoToRustApprovalReplacementReusedNoReprompt  bool     `json:"go_to_rust_approval_replacement_reused_without_reprompt"`
	GoToRustSubstitutedParametersStatus          int      `json:"go_to_rust_substituted_parameters_status"`
	GoToRustPSDeniedOtherRecordStatus            int      `json:"go_to_rust_ps_denied_other_record_status"`
	GoToRust401RetryStatus                       int      `json:"go_to_rust_401_retry_status"`
	GoToRust401ReplayStatus                      int      `json:"go_to_rust_401_replay_status"`
	GoToRust401ReplayMatchesFirst                bool     `json:"go_to_rust_401_replay_matches_first"`
	GoToRust202HeldStatus                        int      `json:"go_to_rust_202_held_status"`
	GoToRust202ForeignTokenStatus                int      `json:"go_to_rust_202_foreign_token_status"`
	GoToRust202PollStatus                        int      `json:"go_to_rust_202_poll_status"`
	GoToRust202ReplayStatus                      int      `json:"go_to_rust_202_replay_status"`
	GoToRustReleaseHeldStatus                    int      `json:"go_to_rust_release_held_status"`
	GoToRustReleasePollStatus                    int      `json:"go_to_rust_release_poll_status"`
	GoToRustReleaseReplayStatus                  int      `json:"go_to_rust_release_replay_status"`
	GoToRustQueryRuns                            int      `json:"go_to_rust_query_runs"`
	ReleaseRetryExpiryError                      string   `json:"release_retry_expiry_error"`
	ReleaseRetryReusedWithoutReprompt            bool     `json:"release_retry_reused_without_reprompt"`
	ReleaseRetryRunsBeforeChallenge              int      `json:"release_retry_runs_before_challenge"`
	ReleaseRetryRunsAfterChallenge               int      `json:"release_retry_runs_after_challenge"`
	ReleaseRetryPollStatus                       int      `json:"release_retry_poll_status"`
	ReleaseRetryOldPendingStatus                 int      `json:"release_retry_old_pending_status"`
	ReleaseRetryBodyMatchesOriginal              bool     `json:"release_retry_body_matches_original"`
	RustToGoPersonStatus                         int      `json:"rust_to_go_person_status"`
	RustToGoClassExchangeStatus                  int      `json:"rust_to_go_class_exchange_status"`
	RustToGoPSFetchedDocument                    bool     `json:"rust_to_go_ps_fetched_document"`
	RustToGoPSIssuanceRecords                    int      `json:"rust_to_go_ps_issuance_records"`
	RustToGoClassReadStatus                      int      `json:"rust_to_go_class_read_status"`
	RustToGoUngrantedDeleteStatus                int      `json:"rust_to_go_ungranted_delete_status"`
	RustToGoProposalExchangeStatus               int      `json:"rust_to_go_proposal_exchange_status"`
	RustToGoProposalExchangeError                string   `json:"rust_to_go_proposal_exchange_error"`
	Reads                                        int      `json:"reads"`
	Deletes                                      []string `json:"deletes"`
	RustPSAuditRecords                           int      `json:"rust_ps_audit_records"`
}

type memoryTokenStore struct {
	mu      sync.Mutex
	records map[string]personserver.PersonTokenRecord
}

func (s *memoryTokenStore) Commit(_ context.Context, r personserver.PersonTokenRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.records == nil {
		s.records = make(map[string]personserver.PersonTokenRecord)
	}
	s.records[r.PersonServer+"|"+r.JTI] = r
	return nil
}

func (s *memoryTokenStore) Load(_ context.Context, issuer, jti string) (personserver.PersonTokenRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[issuer+"|"+jti]
	if !ok {
		return personserver.PersonTokenRecord{}, personserver.ErrPersonTokenNotFound
	}
	return r, nil
}

type memoryIssuanceStore struct {
	mu      sync.Mutex
	records []r3.IssuanceRecord
}

func (s *memoryIssuanceStore) Commit(_ context.Context, r r3.IssuanceRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, r)
	return nil
}

func (s *memoryIssuanceStore) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func bufferedHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)
		for k, vv := range rec.Header() {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		body := rec.Body.Bytes()
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(rec.Code)
		_, _ = w.Write(body)
	})
}

func startTLSServer(host string, handler http.Handler) (*httptest.Server, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{host},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	srv := httptest.NewUnstartedServer(bufferedHandler(handler))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  priv,
		}},
	}
	srv.StartTLS()
	return srv, der, nil
}

func must(err error, step string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", step, err)
		os.Exit(1)
	}
}

func main() {
	if len(os.Args) < 2 {
		must(errors.New("config path argument is required"), "args")
	}
	rawCfg, err := os.ReadFile(os.Args[1])
	must(err, "read config")
	var cfg driverConfig
	must(json.Unmarshal(rawCfg, &cfg), "decode config")

	var currentUnix atomic.Int64
	currentUnix.Store(cfg.InitialNow)
	clock := aauth.ClockFunc(func() time.Time {
		return time.Unix(currentUnix.Load(), 0).UTC()
	})

	certPool := x509.NewCertPool()
	for _, pemBytes := range []string{cfg.APCertPEM, cfg.PSCertPEM, cfg.RecordsCertPEM, cfg.InteropCertPEM} {
		if !certPool.AppendCertsFromPEM([]byte(pemBytes)) {
			must(errors.New("failed to append certificate PEM"), "cert pool")
		}
	}

	var hostMu sync.RWMutex
	hostMap := map[string]string{
		"ap.example":      cfg.APAddr,
		"ps.example":      cfg.PSAddr,
		"records.example": cfg.RecordsAddr,
		"interop.example": cfg.InteropAddr,
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    certPool,
			NextProtos: []string{"http/1.1"},
		},
		ForceAttemptHTTP2: false,
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			host, _, splitErr := net.SplitHostPort(addr)
			if splitErr != nil {
				host = addr
			}
			hostMu.RLock()
			target, ok := hostMap[host]
			hostMu.RUnlock()
			if !ok {
				return nil, fmt.Errorf("unmapped host %q", host)
			}
			var d net.Dialer
			return d.DialContext(ctx, "tcp", target)
		},
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}

	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: httpClient,
		Clock:  clock,
		Admit:  func(context.Context, string) error { return nil },
	})
	must(err, "http key resolver")

	registry, err := r3.NewRegistry(mcp.Vocabulary())
	must(err, "r3 registry")

	readMCP, err := mcp.NewOperation("records.read")
	must(err, "mcp read")
	deleteMCP, err := mcp.NewOperation("records.delete")
	must(err, "mcp delete")
	queryMCP, err := mcp.NewOperation("records.query")
	must(err, "mcp query")
	opSet, err := mcp.NewOperationSet(readMCP, deleteMCP, queryMCP)
	must(err, "mcp operation set")

	seedBytes, err := hex.DecodeString(cfg.AgentSeedHex)
	must(err, "decode agent seed")
	agentKey, err := jose.NewEd25519SigningKey("agent-1", ed25519.NewKeyFromSeed(seedBytes))
	must(err, "agent signing key")

	ctx := context.Background()
	client, err := agent.New(ctx, agent.Config{
		Identifier:  "aauth:clerk@ap.example",
		SigningKey:  agentKey,
		AgentToken:  cfg.AgentToken,
		KeyResolver: resolver,
		HTTPClient:  httpClient,
		Clock:       clock,
		R3:          &agent.R3Config{Registry: registry},
	})
	must(err, "agent client")

	fetchState := func() interopState {
		resp, reqErr := httpClient.Get("https://interop.example/state")
		must(reqErr, "get state")
		defer resp.Body.Close()
		var st interopState
		must(json.NewDecoder(resp.Body).Decode(&st), "decode state")
		currentUnix.Store(st.Now)
		return st
	}

	signedPost := func(uri, token string, body []byte) (*http.Response, []byte) {
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, uri, bytes.NewReader(body))
		must(reqErr, "new post")
		req.Header.Set("Content-Type", "application/json")
		must(signaturekey.SignJWTRequest(req, agentKey, token, clock), "sign post")
		resp, doErr := httpClient.Do(req)
		must(doErr, "do post")
		defer resp.Body.Close()
		respBody, readErr := io.ReadAll(resp.Body)
		must(readErr, "read post body")
		return resp, respBody
	}

	signedGet := func(uri, token string) (*http.Response, []byte) {
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
		must(reqErr, "new get")
		must(signaturekey.SignJWTRequest(req, agentKey, token, clock), "sign get")
		resp, doErr := httpClient.Do(req)
		must(doErr, "do get")
		defer resp.Body.Close()
		respBody, readErr := io.ReadAll(resp.Body)
		must(readErr, "read get body")
		return resp, respBody
	}

	extractProposalToken := func(resp *http.Response) string {
		reqHeader, parseErr := aauth.ParseAuthTokenRequirement(resp.Header.Values("AAuth-Requirement"))
		must(parseErr, "parse AAuth-Requirement")
		_, _, verifyErr := r3.VerifyResourceToken(ctx, reqHeader.ResourceToken, resolver, clock)
		must(verifyErr, "verify proposal resource token")
		return reqHeader.ResourceToken
	}

	var out transcriptOutput

	// ---- Direction 1: Go Agent -> Rust AP + Rust PS + Rust Resource --------
	personRes, err := client.PersonToken(ctx, agent.PersonTokenRequest{
		PersonServer: "https://ps.example",
		Resource:     "https://records.example",
	})
	must(err, "person token")
	personToken, ok := personRes.Token()
	if !ok || personToken == "" {
		must(errors.New("expected immediate person token"), "person token value")
	}
	out.GoToRustPersonTokenIssued = true

	// Arm short class lifetime (30s) and slow human approval (+35s) at Rust PS.
	armResp, err := httpClient.Post("https://interop.example/arm-approval-expiry", "application/json", bytes.NewReader([]byte(`{}`)))
	must(err, "arm approval expiry")
	_ = armResp.Body.Close()

	shortClassRT, err := client.Authorize(ctx, agent.AuthorizeRequest{
		Resource:     "https://records.example",
		PersonToken:  personToken,
		R3Operations: &opSet,
	})
	must(err, "authorize short class")

	shortClassAuth, err := client.Exchange(ctx, agent.ExchangeRequest{
		PersonServer:   "https://ps.example",
		ResourceToken:  shortClassRT,
		PresentedToken: personToken,
	})
	must(err, "exchange short class")
	_, _, _, err = r3.VerifyAuthTokenClaims(ctx, registry, shortClassAuth, resolver, clock)
	must(err, "verify short class auth claims")

	// Direct class read succeeds with 200.
	r1 := []byte(`{"record":"r-1"}`)
	r2 := []byte(`{"record":"r-2"}`)
	readResp, _ := signedPost("https://records.example/records/read", shortClassAuth, r1)
	out.GoToRustClassReadStatus = readResp.StatusCode

	// Per-call 401 challenge on records.delete.
	chalResp, _ := signedPost("https://records.example/records/delete", shortClassAuth, r1)
	out.GoToRust401ChallengeStatus = chalResp.StatusCode
	firstProposalRT := extractProposalToken(chalResp)

	// Slow human approval at Rust PS expires the presented shortClassAuth,
	// records the approval once, and returns 400 expired_presented_token.
	_, exchangeErr := client.Exchange(ctx, agent.ExchangeRequest{
		PersonServer:   "https://ps.example",
		ResourceToken:  firstProposalRT,
		PresentedToken: shortClassAuth,
	})
	var problem *aauth.ProblemError
	if !errors.As(exchangeErr, &problem) {
		must(fmt.Errorf("expected ProblemError on approval expiry, got %v", exchangeErr), "approval expiry")
	}
	out.GoToRustApprovalExpiryError = string(problem.Code)

	stAfterExpiry := fetchState()
	consentsAfterExpiry := len(stAfterExpiry.Consents)

	// Top-down class refresh at the post-approval clock, re-challenge, and
	// replacement exchange reusing the recorded approval without re-prompting.
	refreshedClassRT, err := client.Authorize(ctx, agent.AuthorizeRequest{
		Resource:     "https://records.example",
		PersonToken:  personToken,
		R3Operations: &opSet,
	})
	must(err, "authorize refreshed class")
	classAuth, err := client.Exchange(ctx, agent.ExchangeRequest{
		PersonServer:   "https://ps.example",
		ResourceToken:  refreshedClassRT,
		PresentedToken: personToken,
	})
	must(err, "exchange refreshed class")

	reChalResp, _ := signedPost("https://records.example/records/delete", classAuth, r1)
	if reChalResp.StatusCode != http.StatusUnauthorized {
		must(fmt.Errorf("expected 401 on replacement challenge, got %d", reChalResp.StatusCode), "replacement challenge")
	}
	replacementProposalRT := extractProposalToken(reChalResp)

	perCallAuth, err := client.Exchange(ctx, agent.ExchangeRequest{
		PersonServer:   "https://ps.example",
		ResourceToken:  replacementProposalRT,
		PresentedToken: classAuth,
	})
	must(err, "exchange replacement proposal")
	stAfterReplacement := fetchState()
	out.GoToRustApprovalReplacementReusedNoReprompt = len(stAfterReplacement.Consents) == consentsAfterExpiry

	// Parameter substitution (r-2 with r-1 token) is refused with 403.
	subResp, _ := signedPost("https://records.example/records/delete", perCallAuth, r2)
	out.GoToRustSubstitutedParametersStatus = subResp.StatusCode

	// PS parameter-sensitive consent denies a proposal for r-2 with 403.
	r2ChalResp, _ := signedPost("https://records.example/records/delete", classAuth, r2)
	r2ProposalRT := extractProposalToken(r2ChalResp)
	_, r2ExchangeErr := client.Exchange(ctx, agent.ExchangeRequest{
		PersonServer:   "https://ps.example",
		ResourceToken:  r2ProposalRT,
		PresentedToken: classAuth,
	})
	var r2Problem *aauth.ProblemError
	if errors.As(r2ExchangeErr, &r2Problem) {
		out.GoToRustPSDeniedOtherRecordStatus = r2Problem.Status
	}

	// Retry r-1 delete with perCallAuth succeeds (200) and replay matches (200).
	retryResp, retryBody := signedPost("https://records.example/records/delete", perCallAuth, r1)
	out.GoToRust401RetryStatus = retryResp.StatusCode
	replayResp, replayBody := signedPost("https://records.example/records/delete", perCallAuth, r1)
	out.GoToRust401ReplayStatus = replayResp.StatusCode
	out.GoToRust401ReplayMatchesFirst = bytes.Equal(retryBody, replayBody)

	// Switch Rust Resource to 202 held mode (recomposed from disk).
	holdResp, err := httpClient.Post("https://interop.example/hold-mode", "application/json", bytes.NewReader([]byte(`{}`)))
	must(err, "switch to hold mode")
	_ = holdResp.Body.Close()

	// 202 held execution on records.delete.
	heldResp, _ := signedPost("https://records.example/records/delete", classAuth, r1)
	out.GoToRust202HeldStatus = heldResp.StatusCode
	heldLocation := heldResp.Header.Get("Location")
	heldProposalRT := extractProposalToken(heldResp)
	heldPerCallAuth, err := client.Exchange(ctx, agent.ExchangeRequest{
		PersonServer:   "https://ps.example",
		ResourceToken:  heldProposalRT,
		PresentedToken: classAuth,
	})
	must(err, "exchange 202 held proposal")

	// Foreign token at pending URL is refused with 403.
	foreignResp, _ := signedGet(heldLocation, classAuth)
	out.GoToRust202ForeignTokenStatus = foreignResp.StatusCode

	// Poll and replay with heldPerCallAuth succeed with 200.
	pollResp, _ := signedGet(heldLocation, heldPerCallAuth)
	out.GoToRust202PollStatus = pollResp.StatusCode
	pollReplayResp, _ := signedGet(heldLocation, heldPerCallAuth)
	out.GoToRust202ReplayStatus = pollReplayResp.StatusCode

	// 202 release-gated query (proposal.result) on records.query.
	relResp, _ := signedPost("https://records.example/records/query", classAuth, r1)
	out.GoToRustReleaseHeldStatus = relResp.StatusCode
	relLocation := relResp.Header.Get("Location")
	relProposalRT := extractProposalToken(relResp)
	relPerCallAuth, err := client.Exchange(ctx, agent.ExchangeRequest{
		PersonServer:   "https://ps.example",
		ResourceToken:  relProposalRT,
		PresentedToken: classAuth,
	})
	must(err, "exchange release proposal")
	relPollResp, _ := signedGet(relLocation, relPerCallAuth)
	out.GoToRustReleasePollStatus = relPollResp.StatusCode
	relReplayResp, _ := signedGet(relLocation, relPerCallAuth)
	out.GoToRustReleaseReplayStatus = relReplayResp.StatusCode

	// 202 release retry: the presented class token expires during release
	// approval (short class lifetime, slow approval). The Agent refreshes top
	// down and re-requests the query, which the Resource answers from the held
	// result without running it again; the PS applies the recorded release
	// approval without asking again; the original pending URL is refused.
	armRetryResp, err := httpClient.Post("https://interop.example/arm-approval-expiry", "application/json", bytes.NewReader([]byte(`{}`)))
	must(err, "arm release approval expiry")
	_ = armRetryResp.Body.Close()
	_ = fetchState()
	retryShortRT, err := client.Authorize(ctx, agent.AuthorizeRequest{
		Resource:     "https://records.example",
		PersonToken:  personToken,
		R3Operations: &opSet,
	})
	must(err, "authorize release retry short class")
	retryShortAuth, err := client.Exchange(ctx, agent.ExchangeRequest{
		PersonServer:   "https://ps.example",
		ResourceToken:  retryShortRT,
		PresentedToken: personToken,
	})
	must(err, "exchange release retry short class")
	retryHeldResp, _ := signedPost("https://records.example/records/query", retryShortAuth, r1)
	if retryHeldResp.StatusCode != http.StatusAccepted {
		must(fmt.Errorf("expected 202 on release retry challenge, got %d", retryHeldResp.StatusCode), "release retry challenge")
	}
	retryOldLocation := retryHeldResp.Header.Get("Location")
	retryOldRT := extractProposalToken(retryHeldResp)
	stRetryHeld := fetchState()
	out.ReleaseRetryRunsBeforeChallenge = stRetryHeld.QueryRuns

	_, retryExpiryErr := client.Exchange(ctx, agent.ExchangeRequest{
		PersonServer:   "https://ps.example",
		ResourceToken:  retryOldRT,
		PresentedToken: retryShortAuth,
	})
	var retryProblem *aauth.ProblemError
	if errors.As(retryExpiryErr, &retryProblem) {
		out.ReleaseRetryExpiryError = string(retryProblem.Code)
	}
	stRetryExpired := fetchState()

	retryRefreshedRT, err := client.Authorize(ctx, agent.AuthorizeRequest{
		Resource:     "https://records.example",
		PersonToken:  personToken,
		R3Operations: &opSet,
	})
	must(err, "authorize release retry refreshed class")
	retryClassAuth, err := client.Exchange(ctx, agent.ExchangeRequest{
		PersonServer:   "https://ps.example",
		ResourceToken:  retryRefreshedRT,
		PresentedToken: personToken,
	})
	must(err, "exchange release retry refreshed class")
	retryNewResp, _ := signedPost("https://records.example/records/query", retryClassAuth, r1)
	if retryNewResp.StatusCode != http.StatusAccepted {
		must(fmt.Errorf("expected 202 on release retry re-request, got %d", retryNewResp.StatusCode), "release retry re-request")
	}
	retryNewLocation := retryNewResp.Header.Get("Location")
	retryNewRT := extractProposalToken(retryNewResp)
	stRetryReplacement := fetchState()
	out.ReleaseRetryRunsAfterChallenge = stRetryReplacement.QueryRuns

	retryPerCallAuth, err := client.Exchange(ctx, agent.ExchangeRequest{
		PersonServer:   "https://ps.example",
		ResourceToken:  retryNewRT,
		PresentedToken: retryClassAuth,
	})
	must(err, "exchange release retry replacement proposal")
	stRetryApproved := fetchState()
	out.ReleaseRetryReusedWithoutReprompt = len(stRetryApproved.Consents) == len(stRetryExpired.Consents)

	retryOldResp, _ := signedGet(retryOldLocation, retryPerCallAuth)
	out.ReleaseRetryOldPendingStatus = retryOldResp.StatusCode
	retryPollResp, retryPollBody := signedGet(retryNewLocation, retryPerCallAuth)
	out.ReleaseRetryPollStatus = retryPollResp.StatusCode
	// The released bytes are the computation made at the original challenge.
	var retryReleased struct {
		QueryRunSeq int `json:"query_run_seq"`
	}
	out.ReleaseRetryBodyMatchesOriginal = json.Unmarshal(retryPollBody, &retryReleased) == nil &&
		retryReleased.QueryRunSeq == out.ReleaseRetryRunsBeforeChallenge

	// ---- Direction 2: Rust Agent + Rust Resource <-> Go AP + Go PS ---------
	goAPSeed := bytes.Repeat([]byte{0x21}, ed25519.SeedSize)
	goAPKey, err := jose.NewEd25519SigningKey("go-ap-1", ed25519.NewKeyFromSeed(goAPSeed))
	must(err, "go ap key")
	goPSSeed := bytes.Repeat([]byte{0x31}, ed25519.SeedSize)
	goPSKey, err := jose.NewEd25519SigningKey("go-ps-1", ed25519.NewKeyFromSeed(goPSSeed))
	must(err, "go ps key")
	goAgentSeed := bytes.Repeat([]byte{0x41}, ed25519.SeedSize)
	goAgentKey, err := jose.NewEd25519SigningKey("go-agent-1", ed25519.NewKeyFromSeed(goAgentSeed))
	must(err, "go agent key")

	var goSeq atomic.Int64
	nextID := func() string {
		return fmt.Sprintf("go-id-%d", goSeq.Add(1))
	}

	goAP, err := agentprovider.New(agentprovider.Config{
		Issuer:     "https://go-ap.example",
		SigningKey: goAPKey,
		Clock:      clock,
		NewID:      nextID,
	})
	must(err, "new go ap")
	goAPSrv, goAPDER, err := startTLSServer("go-ap.example", goAP.Handler())
	must(err, "start go ap tls")
	defer goAPSrv.Close()

	goIssuances := &memoryIssuanceStore{}
	var psFetchedDoc atomic.Bool
	var lastRef r3.Reference
	var lastDoc r3.Document
	var lastExact []byte
	var lastMu sync.Mutex

	readR3Op, err := readMCP.ToR3()
	must(err, "read r3 op")
	deleteR3Op, err := deleteMCP.ToR3()
	must(err, "delete r3 op")

	goPS, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer:      "https://go-ps.example",
		SigningKey:  goPSKey,
		KeyResolver: resolver,
		Clock:       clock,
		NewID:       nextID,
		Tokens:      &memoryTokenStore{},
		BindPerson: func(_ context.Context, req personserver.PersonTokenRequest) (personserver.Person, error) {
			if req.Agent != "aauth:clerk@go-ap.example" || req.Resource != "https://records.example" {
				return personserver.Person{}, personserver.ErrAccessDenied
			}
			return personserver.Person{
				Subject:  "go-pairwise-person",
				Lifetime: 30 * time.Minute,
			}, nil
		},
		R3: &personserver.DirectR3Config{
			Registry: registry,
			HTTPClient: &http.Client{
				Timeout: 5 * time.Second,
				Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					resp, rtErr := transport.RoundTrip(req)
					if rtErr != nil || resp == nil || resp.Body == nil {
						return resp, rtErr
					}
					bodyBytes, readErr := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					if readErr != nil {
						return nil, readErr
					}
					lastMu.Lock()
					lastExact = append([]byte(nil), bodyBytes...)
					lastMu.Unlock()
					resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
					return resp, nil
				}),
			},
			Admit: func(_ context.Context, endpoint string) error {
				return nil
			},
			AuthorizeDocument: func(
				_ context.Context,
				_ personserver.AuthorizationRequest,
				ref r3.Reference,
				doc r3.Document,
			) (personserver.DirectR3Decision, error) {
				psFetchedDoc.Store(true)
				lastMu.Lock()
				lastRef = ref
				lastDoc = doc
				lastMu.Unlock()
				granted, grantErr := r3.NewGrantedOperations(mcp.Vocabulary(), readR3Op)
				if grantErr != nil {
					return personserver.DirectR3Decision{}, grantErr
				}
				grant, grantErr := r3.NewGrant(granted, doc)
				if grantErr != nil {
					return personserver.DirectR3Decision{}, grantErr
				}
				return personserver.DirectR3Decision{
					Lifetime: 10 * time.Minute,
					Grant:    grant,
				}, nil
			},
			Issuances: goIssuances,
		},
	})
	must(err, "new go ps")

	goPSMux := http.NewServeMux()
	goPSMux.HandleFunc("POST /__mint-per-call-class", func(w http.ResponseWriter, _ *http.Request) {
		lastMu.Lock()
		ref, doc, exact := lastRef, lastDoc, lastExact
		lastMu.Unlock()
		granted, gErr := r3.NewGrantedOperations(mcp.Vocabulary(), readR3Op)
		must(gErr, "mint granted")
		perCall, pErr := r3.NewGrantedOperations(mcp.Vocabulary(), deleteR3Op)
		must(pErr, "mint per_call")
		authz, aErr := r3.NewAuthorization(granted, perCall, doc)
		must(aErr, "mint authorization")
		nowUnix := clock.Now().Unix()
		tok, mErr := r3.MintAuthToken(registry, goPSKey, aauth.AuthTokenClaims{
			Issuer:       "https://go-ps.example",
			DWK:          aauth.PersonDiscoveryDocument,
			Audience:     "https://records.example",
			JTI:          nextID(),
			PersonServer: "https://go-ps.example",
			Subject:      "go-pairwise-person",
			Confirmation: aauth.Confirmation{JWK: goAgentKey.PublicJWK()},
			IssuedAt:     nowUnix,
			ExpiresAt:    nowUnix + 600,
		}, ref, exact, authz)
		must(mErr, "mint class auth token with r3_per_call")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"auth_token": tok})
	})
	goPSMux.Handle("/", goPS.Handler())

	goPSSrv, goPSDER, err := startTLSServer("go-ps.example", goPSMux)
	must(err, "start go ps tls")
	defer goPSSrv.Close()

	goAPCert, err := x509.ParseCertificate(goAPDER)
	must(err, "parse go ap cert")
	goPSCert, err := x509.ParseCertificate(goPSDER)
	must(err, "parse go ps cert")
	certPool.AddCert(goAPCert)
	certPool.AddCert(goPSCert)

	hostMu.Lock()
	hostMap["go-ap.example"] = goAPSrv.Listener.Addr().String()
	hostMap["go-ps.example"] = goPSSrv.Listener.Addr().String()
	hostMu.Unlock()

	_ = fetchState()
	goAgentToken, err := goAP.Issue(aauth.AgentTokenRequest{
		Agent:        "aauth:clerk@go-ap.example",
		PersonServer: "https://go-ps.example",
		PublicKey:    goAgentKey.PublicJWK(),
		Lifetime:     30 * time.Minute,
	})
	must(err, "issue go agent token")

	convReqBody, err := json.Marshal(converseRequest{
		GoAPAddr:       goAPSrv.Listener.Addr().String(),
		GoAPCertHex:    hex.EncodeToString(goAPDER),
		GoPSAddr:       goPSSrv.Listener.Addr().String(),
		GoPSCertHex:    hex.EncodeToString(goPSDER),
		GoAgentSeedHex: hex.EncodeToString(goAgentSeed),
		GoAgentToken:   goAgentToken,
	})
	must(err, "marshal converse request")

	convHTTPResp, err := httpClient.Post("https://interop.example/converse", "application/json", bytes.NewReader(convReqBody))
	must(err, "post converse")
	defer convHTTPResp.Body.Close()
	if convHTTPResp.StatusCode != http.StatusOK {
		rawErr, _ := io.ReadAll(convHTTPResp.Body)
		must(fmt.Errorf("converse failed (%d): %s", convHTTPResp.StatusCode, string(rawErr)), "converse status")
	}
	var convOut converseResponse
	must(json.NewDecoder(convHTTPResp.Body).Decode(&convOut), "decode converse response")

	out.RustToGoPersonStatus = convOut.PersonStatus
	out.RustToGoClassExchangeStatus = convOut.ClassExchangeStatus
	out.RustToGoPSFetchedDocument = psFetchedDoc.Load()
	out.RustToGoPSIssuanceRecords = goIssuances.len()
	out.RustToGoClassReadStatus = convOut.ClassReadStatus
	out.RustToGoUngrantedDeleteStatus = convOut.UngrantedDeleteStatus
	out.RustToGoProposalExchangeStatus = convOut.ProposalStatus
	out.RustToGoProposalExchangeError = convOut.ProposalError

	finalState := fetchState()
	out.GoToRustQueryRuns = finalState.QueryRuns
	out.Reads = finalState.Reads
	out.Deletes = finalState.Deletes
	out.RustPSAuditRecords = finalState.AuditRecords

	encodedOut, err := json.Marshal(out)
	must(err, "encode transcript")
	fmt.Println(string(encodedOut))
}
