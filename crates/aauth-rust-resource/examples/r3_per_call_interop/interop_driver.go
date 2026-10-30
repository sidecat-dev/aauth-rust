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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/accessserver"
	"gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
	"gitlab.com/sidecat-dev/aauth-go/resource"
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

type federatedConverseRequest struct {
	GoAPAddr          string `json:"go_ap_addr"`
	GoAPCertHex       string `json:"go_ap_cert_hex"`
	FedPSAddr         string `json:"fed_ps_addr"`
	FedPSCertHex      string `json:"fed_ps_cert_hex"`
	FedASAddr         string `json:"fed_as_addr"`
	FedASCertHex      string `json:"fed_as_cert_hex"`
	FedRecordsAddr    string `json:"fed_records_addr"`
	FedRecordsCertHex string `json:"fed_records_cert_hex"`
	GoAgentSeedHex    string `json:"go_agent_seed_hex"`
	FedAgentToken     string `json:"fed_agent_token"`
}

type federatedConverseResponse struct {
	PersonStatus            int  `json:"person_status"`
	ClassExchangeStatus     int  `json:"class_exchange_status"`
	ClassVerified           bool `json:"class_verified"`
	ProposalChallengeStatus int  `json:"proposal_challenge_status"`
	ProposalExchangeStatus  int  `json:"proposal_exchange_status"`
	ProposalVerified        bool `json:"proposal_verified"`
	CompletionStatus        int  `json:"completion_status"`
	ReplayStatus            int  `json:"replay_status"`
	ReplayMatches           bool `json:"replay_matches"`
	HeldChallengeStatus     int  `json:"held_challenge_status"`
	HeldPollTooEarly        bool `json:"held_poll_too_early"`
	HeldPollWait            int  `json:"held_poll_wait"`
	HeldPollStatus          int  `json:"held_poll_status"`
	HeldReplayStatus        int  `json:"held_replay_status"`
	HeldReplayMatches       bool `json:"held_replay_matches"`
}

type transcriptOutput struct {
	GoToRustPersonTokenIssued                   bool     `json:"go_to_rust_person_token_issued"`
	GoToRustClassReadStatus                     int      `json:"go_to_rust_class_read_status"`
	GoToRust401ChallengeStatus                  int      `json:"go_to_rust_401_challenge_status"`
	GoToRustApprovalExpiryError                 string   `json:"go_to_rust_approval_expiry_error"`
	GoToRustApprovalReplacementReusedNoReprompt bool     `json:"go_to_rust_approval_replacement_reused_without_reprompt"`
	GoToRustSubstitutedParametersStatus         int      `json:"go_to_rust_substituted_parameters_status"`
	GoToRustPSDeniedOtherRecordStatus           int      `json:"go_to_rust_ps_denied_other_record_status"`
	GoToRust401RetryStatus                      int      `json:"go_to_rust_401_retry_status"`
	GoToRust401ReplayStatus                     int      `json:"go_to_rust_401_replay_status"`
	GoToRust401ReplayMatchesFirst               bool     `json:"go_to_rust_401_replay_matches_first"`
	GoToRust202HeldStatus                       int      `json:"go_to_rust_202_held_status"`
	GoToRust202ForeignTokenStatus               int      `json:"go_to_rust_202_foreign_token_status"`
	GoToRust202PollStatus                       int      `json:"go_to_rust_202_poll_status"`
	GoToRust202ReplayStatus                     int      `json:"go_to_rust_202_replay_status"`
	GoToRustReleaseHeldStatus                   int      `json:"go_to_rust_release_held_status"`
	GoToRustReleasePollStatus                   int      `json:"go_to_rust_release_poll_status"`
	GoToRustReleaseReplayStatus                 int      `json:"go_to_rust_release_replay_status"`
	GoToRustQueryRuns                           int      `json:"go_to_rust_query_runs"`
	ReleaseRetryExpiryError                     string   `json:"release_retry_expiry_error"`
	ReleaseRetryReusedWithoutReprompt           bool     `json:"release_retry_reused_without_reprompt"`
	ReleaseRetryRunsBeforeChallenge             int      `json:"release_retry_runs_before_challenge"`
	ReleaseRetryRunsAfterChallenge              int      `json:"release_retry_runs_after_challenge"`
	ReleaseRetryPollStatus                      int      `json:"release_retry_poll_status"`
	ReleaseRetryOldPendingStatus                int      `json:"release_retry_old_pending_status"`
	ReleaseRetryBodyMatchesOriginal             bool     `json:"release_retry_body_matches_original"`
	RustToGoPersonStatus                        int      `json:"rust_to_go_person_status"`
	RustToGoClassExchangeStatus                 int      `json:"rust_to_go_class_exchange_status"`
	RustToGoPSFetchedDocument                   bool     `json:"rust_to_go_ps_fetched_document"`
	RustToGoPSIssuanceRecords                   int      `json:"rust_to_go_ps_issuance_records"`
	RustToGoClassReadStatus                     int      `json:"rust_to_go_class_read_status"`
	RustToGoUngrantedDeleteStatus               int      `json:"rust_to_go_ungranted_delete_status"`
	RustToGoProposalExchangeStatus              int      `json:"rust_to_go_proposal_exchange_status"`
	RustToGoProposalExchangeError               string   `json:"rust_to_go_proposal_exchange_error"`
	FederatedPersonStatus                       int      `json:"federated_person_status"`
	FederatedClassExchangeStatus                int      `json:"federated_class_exchange_status"`
	FederatedClassVerified                      bool     `json:"federated_class_verified"`
	FederatedProposalChallengeStatus            int      `json:"federated_proposal_challenge_status"`
	FederatedProposalExchangeStatus             int      `json:"federated_proposal_exchange_status"`
	FederatedProposalVerified                   bool     `json:"federated_proposal_verified"`
	FederatedPSClassConsents                    int      `json:"federated_ps_class_consents"`
	FederatedPSProposalConsents                 int      `json:"federated_ps_proposal_consents"`
	FederatedASClassAuthorizations              int      `json:"federated_as_class_authorizations"`
	FederatedASProposalAuthorizations           int      `json:"federated_as_proposal_authorizations"`
	FederatedASIssuances                        int      `json:"federated_as_issuances"`
	FederatedCompletionStatus                   int      `json:"federated_completion_status"`
	FederatedReplayStatus                       int      `json:"federated_replay_status"`
	FederatedReplayMatches                      bool     `json:"federated_replay_matches"`
	FederatedProtectedRuns                      int      `json:"federated_protected_runs"`
	FederatedHeldChallengeStatus                int      `json:"federated_held_challenge_status"`
	FederatedHeldPollTooEarly                   bool     `json:"federated_held_poll_too_early"`
	FederatedHeldPollWait                       int      `json:"federated_held_poll_wait"`
	FederatedHeldPollStatus                     int      `json:"federated_held_poll_status"`
	FederatedHeldReplayStatus                   int      `json:"federated_held_replay_status"`
	FederatedHeldReplayMatches                  bool     `json:"federated_held_replay_matches"`
	FederatedHeldProtectedRuns                  int      `json:"federated_held_protected_runs"`
	Reads                                       int      `json:"reads"`
	Deletes                                     []string `json:"deletes"`
	RustPSAuditRecords                          int      `json:"rust_ps_audit_records"`
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

type memoryDocumentStore struct {
	mu      sync.Mutex
	records map[string]resource.R3DocumentRecord
}

func (s *memoryDocumentStore) Commit(_ context.Context, record resource.R3DocumentRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.records == nil {
		s.records = make(map[string]resource.R3DocumentRecord)
	}
	key := record.Reference.URI()
	if existing, ok := s.records[key]; ok {
		if !bytes.Equal(existing.ExactJSON, record.ExactJSON) ||
			existing.PersonServer != record.PersonServer ||
			existing.AuthTokenIssuer != record.AuthTokenIssuer ||
			existing.AuthTokenIssuerDocument != record.AuthTokenIssuerDocument {
			return resource.ErrR3DocumentConflict
		}
		return nil
	}
	s.records[key] = record.Clone()
	return nil
}

func (s *memoryDocumentStore) Load(_ context.Context, uri string) (resource.R3DocumentRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[uri]
	if !ok {
		return resource.R3DocumentRecord{}, resource.ErrR3DocumentNotFound
	}
	return record.Clone(), nil
}

type memoryProposalStore struct {
	mu      sync.Mutex
	records map[string]resource.R3ProposalRecord
}

func (s *memoryProposalStore) Commit(_ context.Context, record resource.R3ProposalRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.records == nil {
		s.records = make(map[string]resource.R3ProposalRecord)
	}
	key := record.Reference.URI()
	if _, ok := s.records[key]; ok {
		return resource.ErrR3ProposalConflict
	}
	cloned := record
	cloned.ExactJSON = append([]byte(nil), record.ExactJSON...)
	s.records[key] = cloned
	return nil
}

func (s *memoryProposalStore) Load(_ context.Context, uri string) (resource.R3ProposalRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[uri]
	if !ok {
		return resource.R3ProposalRecord{}, resource.ErrR3ProposalNotFound
	}
	record.ExactJSON = append([]byte(nil), record.ExactJSON...)
	return record, nil
}

type memoryRetryEntry struct {
	invocation resource.R3RetryInvocation
	state      string
	token      resource.R3RetryAuthToken
	fence      string
	response   resource.HeldResponse
}

type memoryRetryStore struct {
	mu      sync.Mutex
	records map[string]*memoryRetryEntry
}

func (s *memoryRetryStore) Prepare(_ context.Context, invocation resource.R3RetryInvocation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.records == nil {
		s.records = make(map[string]*memoryRetryEntry)
	}
	key := invocation.Reference.URI()
	if _, ok := s.records[key]; ok {
		return resource.ErrR3RetryConflict
	}
	cloned := invocation
	cloned.ExactProposal = append([]byte(nil), invocation.ExactProposal...)
	cloned.RequiredScopes = append([]string(nil), invocation.RequiredScopes...)
	s.records[key] = &memoryRetryEntry{invocation: cloned, state: "pending"}
	return nil
}

func (s *memoryRetryStore) Load(_ context.Context, reference r3.Reference) (resource.R3RetryInvocation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.records[reference.URI()]
	if !ok {
		return resource.R3RetryInvocation{}, resource.ErrR3RetryNotFound
	}
	invocation := entry.invocation
	invocation.ExactProposal = append([]byte(nil), invocation.ExactProposal...)
	invocation.RequiredScopes = append([]string(nil), invocation.RequiredScopes...)
	return invocation, nil
}

func (s *memoryRetryStore) Claim(_ context.Context, reference r3.Reference, token resource.R3RetryAuthToken) (resource.R3RetryClaim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.records[reference.URI()]
	if !ok {
		return resource.R3RetryClaim{}, resource.ErrR3RetryNotFound
	}
	switch entry.state {
	case "pending":
		if !token.PresentedAt.Before(entry.invocation.CompletionUntil) {
			return resource.R3RetryClaim{}, resource.ErrR3RetryExpired
		}
		entry.state = "executing"
		entry.token = token
		entry.fence = "fence-1"
		return resource.NewHeldExecution(resource.HeldExecution{
			InvocationID: reference.URI(),
			Fence:        entry.fence,
		}), nil
	case "executing":
		return resource.R3RetryClaim{}, resource.ErrR3RetryConflict
	case "completed":
		if entry.token.SHA256 != token.SHA256 {
			return resource.R3RetryClaim{}, resource.ErrR3RetryTokenMismatch
		}
		return resource.NewHeldReplay(entry.response), nil
	case "unresolved":
		return resource.R3RetryClaim{}, resource.ErrR3RetryUnresolved
	default:
		return resource.R3RetryClaim{}, resource.ErrR3RetryConflict
	}
}

func (s *memoryRetryStore) Retain(_ context.Context, execution resource.R3RetryExecution, response resource.HeldResponse) (resource.HeldResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.records[execution.InvocationID]
	if !ok || entry.state != "executing" || entry.fence != execution.Fence {
		return resource.HeldResponse{}, resource.ErrR3RetryCompletionStale
	}
	entry.response = resource.HeldResponse{
		StatusCode: response.StatusCode,
		Header:     response.Header.Clone(),
		Body:       append([]byte(nil), response.Body...),
		Trailer:    response.Trailer.Clone(),
	}
	entry.state = "completed"
	return resource.HeldResponse{
		StatusCode: entry.response.StatusCode,
		Header:     entry.response.Header.Clone(),
		Body:       append([]byte(nil), entry.response.Body...),
		Trailer:    entry.response.Trailer.Clone(),
	}, nil
}

// memoryHeldStore follows the pin test store in resource/held_test.go.
// The pending identifier and fence are store-local. They are not wire fields.
// One slot is enough: only POST /records/held-1 is selected for held delivery.
const heldPendingID = "held-call-0123456789abcdef"

type memoryHeldStore struct {
	mu         sync.Mutex
	invocation resource.HeldInvocation
	state      string
	token      resource.HeldAuthToken
	response   resource.HeldResponse
}

func (s *memoryHeldStore) Create(_ context.Context, invocation resource.HeldInvocation) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.invocation = cloneHeldInvocation(invocation)
	s.state = "pending"
	return heldPendingID, nil
}

func (s *memoryHeldStore) Load(_ context.Context, id string) (resource.HeldInvocation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id != heldPendingID || s.state == "" {
		return resource.HeldInvocation{}, resource.ErrHeldInvocationNotFound
	}
	return cloneHeldInvocation(s.invocation), nil
}

func (s *memoryHeldStore) Claim(_ context.Context, id string, token resource.HeldAuthToken) (resource.HeldClaim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id != heldPendingID || s.state == "" {
		return resource.HeldClaim{}, resource.ErrHeldInvocationNotFound
	}
	switch s.state {
	case "pending":
		if !token.PresentedAt.Before(s.invocation.CompletionUntil) {
			s.state = "expired"
			return resource.HeldClaim{}, resource.ErrHeldInvocationExpired
		}
		s.state = "executing"
		s.token = token
		return resource.NewHeldExecution(resource.HeldExecution{
			InvocationID: heldPendingID,
			Fence:        "held-fence-1",
		}), nil
	case "executing":
		return resource.HeldClaim{}, resource.ErrHeldInvocationConflict
	case "complete":
		if s.token.SHA256 != token.SHA256 {
			return resource.HeldClaim{}, resource.ErrHeldAuthTokenMismatch
		}
		return resource.NewHeldReplay(s.response), nil
	case "expired":
		return resource.HeldClaim{}, resource.ErrHeldInvocationExpired
	default:
		return resource.HeldClaim{}, resource.ErrHeldExecutionUnresolved
	}
}

func (s *memoryHeldStore) Retain(_ context.Context, execution resource.HeldExecution, response resource.HeldResponse) (resource.HeldResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != "executing" || execution != (resource.HeldExecution{InvocationID: heldPendingID, Fence: "held-fence-1"}) {
		return resource.HeldResponse{}, resource.ErrHeldCompletionStale
	}
	s.response = resource.HeldResponse{
		StatusCode: response.StatusCode,
		Header:     response.Header.Clone(),
		Body:       append([]byte(nil), response.Body...),
		Trailer:    response.Trailer.Clone(),
	}
	s.state = "complete"
	return resource.HeldResponse{
		StatusCode: s.response.StatusCode,
		Header:     s.response.Header.Clone(),
		Body:       append([]byte(nil), s.response.Body...),
		Trailer:    s.response.Trailer.Clone(),
	}, nil
}

func cloneHeldInvocation(invocation resource.HeldInvocation) resource.HeldInvocation {
	invocation.Header = invocation.Header.Clone()
	invocation.Body = append([]byte(nil), invocation.Body...)
	invocation.RequiredScopes = append([]string(nil), invocation.RequiredScopes...)
	if invocation.R3PerCall != nil {
		cloned := *invocation.R3PerCall
		cloned.ExactProposal = append([]byte(nil), invocation.R3PerCall.ExactProposal...)
		invocation.R3PerCall = &cloned
	}
	return invocation
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

	// Direction 3: Rust Agent against a separate Go federated Resource,
	// Access Server, and Person Server. The DirectR3 servers above stay
	// class-only and are not reused.
	_ = fetchState()
	fedAgentToken, err := goAP.Issue(aauth.AgentTokenRequest{
		Agent:        "aauth:federated@go-ap.example",
		PersonServer: "https://fed-ps.example",
		PublicKey:    goAgentKey.PublicJWK(),
		Lifetime:     30 * time.Minute,
	})
	must(err, "issue federated agent token")
	fedOut, fedCounts := federatedExchange(federatedExchangeConfig{
		Clock:         clock,
		Resolver:      resolver,
		Registry:      registry,
		HTTPClient:    httpClient,
		CertPool:      certPool,
		HostMu:        &hostMu,
		HostMap:       hostMap,
		GoAPAddr:      goAPSrv.Listener.Addr().String(),
		GoAPDER:       goAPDER,
		GoAgentSeed:   goAgentSeed,
		FedAgentToken: fedAgentToken,
		DeleteOp:      deleteR3Op,
	})
	out.FederatedPersonStatus = fedOut.PersonStatus
	out.FederatedClassExchangeStatus = fedOut.ClassExchangeStatus
	out.FederatedClassVerified = fedOut.ClassVerified
	out.FederatedProposalChallengeStatus = fedOut.ProposalChallengeStatus
	out.FederatedProposalExchangeStatus = fedOut.ProposalExchangeStatus
	out.FederatedProposalVerified = fedOut.ProposalVerified
	out.FederatedPSClassConsents = fedCounts.PSClassConsents
	out.FederatedPSProposalConsents = fedCounts.PSProposalConsents
	out.FederatedASClassAuthorizations = fedCounts.ASClassAuthorizations
	out.FederatedASProposalAuthorizations = fedCounts.ASProposalAuthorizations
	out.FederatedASIssuances = fedCounts.ASIssuances
	out.FederatedCompletionStatus = fedOut.CompletionStatus
	out.FederatedReplayStatus = fedOut.ReplayStatus
	out.FederatedReplayMatches = fedOut.ReplayMatches
	out.FederatedProtectedRuns = fedCounts.ProtectedRuns
	out.FederatedHeldChallengeStatus = fedOut.HeldChallengeStatus
	out.FederatedHeldPollTooEarly = fedOut.HeldPollTooEarly
	out.FederatedHeldPollWait = fedOut.HeldPollWait
	out.FederatedHeldPollStatus = fedOut.HeldPollStatus
	out.FederatedHeldReplayStatus = fedOut.HeldReplayStatus
	out.FederatedHeldReplayMatches = fedOut.HeldReplayMatches
	out.FederatedHeldProtectedRuns = fedCounts.HeldProtectedRuns

	finalState := fetchState()
	out.GoToRustQueryRuns = finalState.QueryRuns
	out.Reads = finalState.Reads
	out.Deletes = finalState.Deletes
	out.RustPSAuditRecords = finalState.AuditRecords

	encodedOut, err := json.Marshal(out)
	must(err, "encode transcript")
	fmt.Println(string(encodedOut))
}

const (
	fedPSIssuer       = "https://fed-ps.example"
	fedASIssuer       = "https://fed-as.example"
	fedResourceIssuer = "https://fed-records.example"
)

type federatedExchangeConfig struct {
	Clock         aauth.Clock
	Resolver      signaturekey.KeyResolver
	Registry      r3.Registry
	HTTPClient    *http.Client
	CertPool      *x509.CertPool
	HostMu        *sync.RWMutex
	HostMap       map[string]string
	GoAPAddr      string
	GoAPDER       []byte
	GoAgentSeed   []byte
	FedAgentToken string
	DeleteOp      r3.Operation
}

type federatedCounts struct {
	PSClassConsents          int
	PSProposalConsents       int
	ASClassAuthorizations    int
	ASProposalAuthorizations int
	ASIssuances              int
	ProtectedRuns            int
	HeldProtectedRuns        int
}

func federatedExchange(cfg federatedExchangeConfig) (federatedConverseResponse, federatedCounts) {
	fedResourceSeed := bytes.Repeat([]byte{0x51}, ed25519.SeedSize)
	fedResourceKey, err := jose.NewEd25519SigningKey("fed-resource-1", ed25519.NewKeyFromSeed(fedResourceSeed))
	must(err, "fed resource key")
	fedASSeed := bytes.Repeat([]byte{0x61}, ed25519.SeedSize)
	fedASKey, err := jose.NewEd25519SigningKey("fed-as-1", ed25519.NewKeyFromSeed(fedASSeed))
	must(err, "fed access key")
	fedPSSeed := bytes.Repeat([]byte{0x71}, ed25519.SeedSize)
	fedPSKey, err := jose.NewEd25519SigningKey("fed-ps-1", ed25519.NewKeyFromSeed(fedPSSeed))
	must(err, "fed person key")

	var fedIDs atomic.Int64
	nextID := func() string {
		return fmt.Sprintf("fed-%d", fedIDs.Add(1))
	}
	definitions, err := r3.NewDefinitionRegistry(mcp.DefinitionRegistration())
	must(err, "fed definition registry")
	definitionSource := mcp.NewToolsListSnapshot(mcp.NewInitialToolsListPage([]byte(
		`{"tools":[{"name":"records.delete","inputSchema":{"type":"object"}}]}`,
	)))
	definition, err := mcp.ParseDefinition(fedResourceIssuer+"/mcp", definitionSource)
	must(err, "fed mcp definition")

	var psClassConsents atomic.Int32
	var psProposalConsents atomic.Int32
	var asClassAuthorizations atomic.Int32
	var asProposalAuthorizations atomic.Int32
	var protectedRuns atomic.Int32
	var heldRuns atomic.Int32
	issuances := &memoryIssuanceStore{}
	admitResource := func(_ context.Context, endpoint string) error {
		if !strings.HasPrefix(endpoint, fedResourceIssuer+"/r3/") {
			return errors.New("federated interop: unexpected R3 endpoint")
		}
		return nil
	}

	fedResource, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer:       fedResourceIssuer,
		AccessServer: fedASIssuer,
		SigningKey:   fedResourceKey,
		KeyResolver:  cfg.Resolver,
		Clock:        cfg.Clock,
		NewID:        nextID,
		ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, personContext resource.PersonContext) error {
			if identity.Issuer != fedPSIssuer || identity.Subject != "fed-person" || personContext.Tenant != "" {
				return errors.New("federated interop: unexpected person")
			}
			return nil
		},
		Protected: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/records/r-1":
				protectedRuns.Add(1)
			case "/records/held-1":
				heldRuns.Add(1)
			default:
				http.Error(w, "unexpected protected path", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"deleted":true}`))
		}),
		// Hold only the separate path. A nil selector would hold every request,
		// including the existing POST /records/r-1 challenge. Budget stays unset:
		// Go refuses Budget together with HeldInvocations.
		HeldInvocations: &memoryHeldStore{},
		HoldAuthTokenRequest: func(request *http.Request) bool {
			return request.Method == http.MethodPost && request.URL.Path == "/records/held-1"
		},
		MaxSignedBodyBytes:           1 << 20,
		MaxRetainedRequestBodyBytes:  64 << 10,
		MaxRetainedResponseBodyBytes: 64 << 10,
		MaxRetainedHeaderBytes:       16 << 10,
		R3: &resource.R3Config{
			Registry:    cfg.Registry,
			Definitions: definitions,
			Vocabularies: []resource.R3VocabularyConfig{{
				Definition: definition,
			}},
			Documents: &memoryDocumentStore{},
			HTTP: resource.R3HTTPAdapter{
				OperationForRequest: func(request *http.Request) (r3.Operation, bool, error) {
					if request.Method == http.MethodPost && strings.HasPrefix(request.URL.Path, "/records/") {
						return cfg.DeleteOp, true, nil
					}
					return r3.Operation{}, false, nil
				},
				PresentParameters: func(request *http.Request, _ r3.Operation) (map[string]r3.PresentedParameter, error) {
					record := strings.TrimPrefix(request.URL.Path, "/records/")
					if record == "" || record == request.URL.Path || strings.Contains(record, "/") {
						return nil, errors.New("federated interop: unexpected record path")
					}
					encoded, marshalErr := json.Marshal(record)
					if marshalErr != nil {
						return nil, marshalErr
					}
					presented, presentErr := r3.NewPresentedInlineParameter(encoded)
					if presentErr != nil {
						return nil, presentErr
					}
					return map[string]r3.PresentedParameter{"record": presented}, nil
				},
			},
			PerCall: &resource.R3PerCallConfig{
				Proposals: &memoryProposalStore{},
				Retries:   &memoryRetryStore{},
				DescribeCall: func(_ context.Context, invocation r3.Invocation, account *string) (resource.R3CallDescription, error) {
					if account != nil {
						return resource.R3CallDescription{}, errors.New("federated interop: account is not used")
					}
					presented, ok := invocation.PresentedParameters()["record"]
					if !ok {
						return resource.R3CallDescription{}, errors.New("federated interop: missing record")
					}
					encoded, ok := presented.InlineJSON()
					if !ok {
						return resource.R3CallDescription{}, errors.New("federated interop: record is not inline")
					}
					inline, inlineErr := r3.NewInlineParameter(encoded)
					if inlineErr != nil {
						return resource.R3CallDescription{}, inlineErr
					}
					parameters, paramErr := r3.NewParameters(map[string]r3.Parameter{"record": inline})
					if paramErr != nil {
						return resource.R3CallDescription{}, paramErr
					}
					return resource.R3CallDescription{Parameters: parameters}, nil
				},
			},
		},
	})
	must(err, "new federated resource")

	fedAS, err := accessserver.New(accessserver.Config{
		Issuer:      fedASIssuer,
		SigningKey:  fedASKey,
		KeyResolver: cfg.Resolver,
		Clock:       cfg.Clock,
		NewID:       nextID,
		TrustPersonServer: func(_ context.Context, issuer string) error {
			if issuer != fedPSIssuer {
				return errors.New("federated interop: untrusted person server")
			}
			return nil
		},
		Authorize: func(context.Context, accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			return accessserver.Decision{}, errors.New("federated interop: core policy must not receive an R3 request")
		},
		R3: &accessserver.R3Config{
			Registry:   cfg.Registry,
			HTTPClient: cfg.HTTPClient,
			Admit:      admitResource,
			AuthorizeDocument: func(_ context.Context, _ accessserver.AuthorizationRequest, _ r3.Reference, document r3.Document) (accessserver.R3DocumentDecision, error) {
				typed, opErr := mcp.NewOperation("records.delete")
				if opErr != nil {
					return accessserver.R3DocumentDecision{}, opErr
				}
				wanted, setErr := mcp.NewOperationSet(typed)
				if setErr != nil {
					return accessserver.R3DocumentDecision{}, setErr
				}
				same, equalErr := document.OperationSet().Equal(wanted)
				if equalErr != nil || !same {
					return accessserver.R3DocumentDecision{}, errors.New("federated interop: class document is not records.delete")
				}
				empty, grantErr := r3.NewGrantedOperations(mcp.Vocabulary())
				if grantErr != nil {
					return accessserver.R3DocumentDecision{}, grantErr
				}
				perCall, grantErr := r3.NewGrantedOperations(mcp.Vocabulary(), cfg.DeleteOp)
				if grantErr != nil {
					return accessserver.R3DocumentDecision{}, grantErr
				}
				authorization, authErr := r3.NewAuthorization(empty, perCall, document)
				if authErr != nil {
					return accessserver.R3DocumentDecision{}, authErr
				}
				asClassAuthorizations.Add(1)
				return accessserver.R3DocumentDecision{
					Lifetime:      10 * time.Minute,
					Authorization: &authorization,
				}, nil
			},
			AuthorizeProposal: func(_ context.Context, _ accessserver.AuthorizationRequest, _ r3.Reference, proposal r3.Proposal) (accessserver.R3ProposalDecision, error) {
				same, equalErr := proposal.Operation().Equal(cfg.DeleteOp)
				if equalErr != nil || !same {
					return accessserver.R3ProposalDecision{}, errors.New("federated interop: proposal operation is not records.delete")
				}
				asProposalAuthorizations.Add(1)
				return accessserver.R3ProposalDecision{Lifetime: 5 * time.Minute}, nil
			},
			Issuances: issuances,
		},
	})
	must(err, "new federated access server")

	fedPS, err := personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer:      fedPSIssuer,
		SigningKey:  fedPSKey,
		KeyResolver: cfg.Resolver,
		Clock:       cfg.Clock,
		NewID:       nextID,
		HTTPClient:  cfg.HTTPClient,
		Tokens:      &memoryTokenStore{},
		AccessServerEndpoint: func(_ context.Context, issuer string) (string, error) {
			if issuer != fedASIssuer {
				return "", errors.New("federated interop: unknown access server")
			}
			return fedASIssuer + "/token", nil
		},
		BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
			if request.Agent != "aauth:federated@go-ap.example" || request.Resource != fedResourceIssuer {
				return personserver.Person{}, personserver.ErrAccessDenied
			}
			return personserver.Person{Subject: "fed-person", Lifetime: 30 * time.Minute}, nil
		},
		Consent: func(context.Context, personserver.AuthorizationRequest) error {
			return errors.New("federated interop: core consent must not receive an R3 request")
		},
		R3: &personserver.R3Config{
			Registry: cfg.Registry,
			Admit:    admitResource,
			ConsentDocument: func(context.Context, personserver.AuthorizationRequest, r3.Reference, r3.Document) error {
				psClassConsents.Add(1)
				return nil
			},
			ConsentProposal: func(context.Context, personserver.AuthorizationRequest, r3.Reference, r3.Proposal) error {
				psProposalConsents.Add(1)
				return nil
			},
		},
	})
	must(err, "new federated person server")

	fedPSSrv, fedPSDER, err := startTLSServer("fed-ps.example", fedPS.Handler())
	must(err, "start fed ps tls")
	defer fedPSSrv.Close()
	fedASSrv, fedASDER, err := startTLSServer("fed-as.example", fedAS.Handler())
	must(err, "start fed as tls")
	defer fedASSrv.Close()
	fedRecordsSrv, fedRecordsDER, err := startTLSServer("fed-records.example", fedResource.Handler())
	must(err, "start fed resource tls")
	defer fedRecordsSrv.Close()

	for _, der := range [][]byte{fedPSDER, fedASDER, fedRecordsDER} {
		cert, parseErr := x509.ParseCertificate(der)
		must(parseErr, "parse fed cert")
		cfg.CertPool.AddCert(cert)
	}
	cfg.HostMu.Lock()
	cfg.HostMap["fed-ps.example"] = fedPSSrv.Listener.Addr().String()
	cfg.HostMap["fed-as.example"] = fedASSrv.Listener.Addr().String()
	cfg.HostMap["fed-records.example"] = fedRecordsSrv.Listener.Addr().String()
	cfg.HostMu.Unlock()

	body, err := json.Marshal(federatedConverseRequest{
		GoAPAddr:          cfg.GoAPAddr,
		GoAPCertHex:       hex.EncodeToString(cfg.GoAPDER),
		FedPSAddr:         fedPSSrv.Listener.Addr().String(),
		FedPSCertHex:      hex.EncodeToString(fedPSDER),
		FedASAddr:         fedASSrv.Listener.Addr().String(),
		FedASCertHex:      hex.EncodeToString(fedASDER),
		FedRecordsAddr:    fedRecordsSrv.Listener.Addr().String(),
		FedRecordsCertHex: hex.EncodeToString(fedRecordsDER),
		GoAgentSeedHex:    hex.EncodeToString(cfg.GoAgentSeed),
		FedAgentToken:     cfg.FedAgentToken,
	})
	must(err, "marshal federated converse")
	fedClient := &http.Client{Transport: cfg.HTTPClient.Transport, Timeout: 30 * time.Second}
	resp, err := fedClient.Post("https://interop.example/federated-converse", "application/json", bytes.NewReader(body))
	must(err, "post federated converse")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		rawErr, _ := io.ReadAll(resp.Body)
		must(fmt.Errorf("federated converse failed (%d): %s", resp.StatusCode, string(rawErr)), "federated converse status")
	}
	var out federatedConverseResponse
	must(json.NewDecoder(resp.Body).Decode(&out), "decode federated converse")
	return out, federatedCounts{
		PSClassConsents:          int(psClassConsents.Load()),
		PSProposalConsents:       int(psProposalConsents.Load()),
		ASClassAuthorizations:    int(asClassAuthorizations.Load()),
		ASProposalAuthorizations: int(asProposalAuthorizations.Load()),
		ASIssuances:              issuances.len(),
		ProtectedRuns:            int(protectedRuns.Load()),
		HeldProtectedRuns:        int(heldRuns.Load()),
	}
}
