// Package ees - UPF Event Exposure Service (EES)
// nrf.go: register the nupf-ee service with an NRF (ees.nrfUri).
//
// An SMF that uses OAuth2 towards the UPF must obtain a token from the NRF for
// target NF type UPF, and the NRF only issues it for a registered UPF profile.
// The registrar keeps such a profile registered while the EES API runs
// (TS 29.510 NFRegister / NFUpdate heartbeat / NFDeregister).

package ees

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	nrfNFMPath            = "/nnrf-nfm/v1/nf-instances/"
	nrfTokenPath          = "/oauth2/token"
	nrfDefaultHeartbeat   = 60 * time.Second
	nrfRetryMin           = time.Second
	nrfRetryMax           = 30 * time.Second
	nrfDeregisterDeadline = 3 * time.Second
)

// NRFRegistrar keeps the UPF nupf-ee profile registered in an NRF.
type NRFRegistrar struct {
	nrfRoot    string // scheme://host[:port], no trailing slash
	instanceID string
	profile    []byte
	client     *http.Client
	logger     *logrus.Entry

	mu          sync.Mutex
	token       string
	tokenExpiry time.Time
	heartbeat   time.Duration
}

type nrfIPEndPoint struct {
	Ipv4Address string `json:"ipv4Address"`
	Transport   string `json:"transport"`
	Port        int    `json:"port"`
}

type nrfService struct {
	ServiceInstanceID string           `json:"serviceInstanceId"`
	ServiceName       string           `json:"serviceName"`
	Versions          []map[string]any `json:"versions"`
	Scheme            string           `json:"scheme"`
	NfServiceStatus   string           `json:"nfServiceStatus"`
	IPEndPoints       []nrfIPEndPoint  `json:"ipEndPoints"`
}

type nrfProfile struct {
	NfInstanceID  string       `json:"nfInstanceId"`
	NfType        string       `json:"nfType"`
	NfStatus      string       `json:"nfStatus"`
	Ipv4Addresses []string     `json:"ipv4Addresses"`
	NfServices    []nrfService `json:"nfServices"`
}

// NewNRFRegistrar validates nrfURI and builds the UPF profile advertising the
// EES API at apiIPv4:apiPort over http.
func NewNRFRegistrar(nrfURI, apiIPv4 string, apiPort int, logger *logrus.Entry) (*NRFRegistrar, error) {
	root, err := url.Parse(nrfURI)
	if err != nil || (root.Scheme != "http" && root.Scheme != "https") || root.Host == "" ||
		root.User != nil || root.RawQuery != "" || root.Fragment != "" || strings.Trim(root.Path, "/") != "" {
		return nil, errors.New("must be an absolute http(s) URI without a path, e.g. http://127.0.0.10:8000")
	}
	ip := net.ParseIP(apiIPv4).To4()
	if ip == nil || ip.IsUnspecified() {
		return nil, fmt.Errorf("advertised EES address %q must be a specific IPv4 address (set ees.ip)", apiIPv4)
	}
	instanceID, err := newUUIDv4()
	if err != nil {
		return nil, err
	}
	profile, err := json.Marshal(nrfProfile{
		NfInstanceID: instanceID, NfType: "UPF", NfStatus: "REGISTERED",
		Ipv4Addresses: []string{ip.String()},
		NfServices: []nrfService{{
			ServiceInstanceID: "nupf-ee", ServiceName: "nupf-ee",
			Versions: []map[string]any{{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}},
			Scheme:   "http", NfServiceStatus: "REGISTERED",
			IPEndPoints: []nrfIPEndPoint{{Ipv4Address: ip.String(), Transport: "TCP", Port: apiPort}},
		}},
	})
	if err != nil {
		return nil, err
	}
	return &NRFRegistrar{
		nrfRoot: root.Scheme + "://" + root.Host, instanceID: instanceID, profile: profile,
		client: &http.Client{Timeout: 5 * time.Second}, logger: logger, heartbeat: nrfDefaultHeartbeat,
	}, nil
}

// InstanceID is the NF instance ID registered for this UPF.
func (r *NRFRegistrar) InstanceID() string { return r.instanceID }

// Run registers, sends heartbeats until ctx is done, then deregisters.
func (r *NRFRegistrar) Run(ctx context.Context) {
	if !r.registerWithRetry(ctx) {
		return
	}
	defer r.deregister()
	for {
		r.mu.Lock()
		wait := r.heartbeat
		r.mu.Unlock()
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		status, err := r.sendHeartbeat(ctx)
		switch {
		case err != nil:
			r.logger.Warnf("nrf heartbeat failed: %v", err)
		case status == http.StatusNotFound:
			r.logger.Warn("nrf no longer knows this UPF; registering again")
			if !r.registerWithRetry(ctx) {
				return
			}
		case status/100 != 2:
			r.logger.Warnf("nrf heartbeat rejected: HTTP %d", status)
		}
	}
}

func (r *NRFRegistrar) registerWithRetry(ctx context.Context) bool {
	backoff := nrfRetryMin
	for {
		err := r.register(ctx)
		if err == nil {
			return true
		}
		r.logger.Warnf("nrf registration failed, retrying in %v: %v", backoff, err)
		select {
		case <-ctx.Done():
			return false
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, nrfRetryMax)
	}
}

// register sends NFRegister (PUT); NFRegister is not OAuth2-protected.
func (r *NRFRegistrar) register(ctx context.Context) error {
	status, body, err := r.do(ctx, http.MethodPut, r.nrfRoot+nrfNFMPath+r.instanceID, "application/json",
		r.profile, false)
	if err != nil {
		return err
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return fmt.Errorf("HTTP %d", status)
	}
	var registered struct {
		HeartBeatTimer int `json:"heartBeatTimer"`
	}
	if json.Unmarshal(body, &registered) == nil && registered.HeartBeatTimer > 0 {
		r.mu.Lock()
		r.heartbeat = time.Duration(registered.HeartBeatTimer) * time.Second
		r.mu.Unlock()
	}
	r.logger.Infof("registered nupf-ee with NRF %s as UPF instance %s", r.nrfRoot, r.instanceID)
	return nil
}

func (r *NRFRegistrar) sendHeartbeat(ctx context.Context) (int, error) {
	patch := []byte(`[{"op":"replace","path":"/nfStatus","value":"REGISTERED"}]`)
	status, _, err := r.do(ctx, http.MethodPatch, r.nrfRoot+nrfNFMPath+r.instanceID,
		"application/json-patch+json", patch, true)
	return status, err
}

func (r *NRFRegistrar) deregister() {
	ctx, cancel := context.WithTimeout(context.Background(), nrfDeregisterDeadline)
	defer cancel()
	status, _, err := r.do(ctx, http.MethodDelete, r.nrfRoot+nrfNFMPath+r.instanceID, "", nil, true)
	if err != nil {
		r.logger.Warnf("nrf deregistration failed: %v", err)
		return
	}
	if status/100 != 2 && status != http.StatusNotFound {
		r.logger.Warnf("nrf deregistration rejected: HTTP %d", status)
		return
	}
	r.logger.Infof("deregistered UPF instance %s from NRF", r.instanceID)
}

// do sends one request and returns its status and (bounded) body. With auth, a
// cached token is attached and a 401 is retried once with a fresh token (the
// NRF protects NFUpdate/NFDeregister when OAuth2 is enabled).
func (r *NRFRegistrar) do(ctx context.Context, method, target, contentType string, body []byte,
	auth bool,
) (int, []byte, error) {
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
		if err != nil {
			return 0, nil, err
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		if auth {
			if token := r.cachedToken(); token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}
		}
		rsp, err := r.client.Do(req)
		if err != nil {
			return 0, nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(rsp.Body, 1<<20))
		if closeErr := rsp.Body.Close(); readErr == nil {
			readErr = closeErr
		}
		if readErr != nil {
			return 0, nil, readErr
		}
		if !auth || rsp.StatusCode != http.StatusUnauthorized || attempt > 0 {
			return rsp.StatusCode, data, nil
		}
		if err := r.fetchToken(ctx); err != nil {
			return 0, nil, fmt.Errorf("oauth2 token: %w", err)
		}
	}
}

func (r *NRFRegistrar) cachedToken() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.token == "" || time.Now().After(r.tokenExpiry) {
		return ""
	}
	return r.token
}

// fetchToken requests an nnrf-nfm access token (TS 29.510 AccessTokenRequest).
func (r *NRFRegistrar) fetchToken(ctx context.Context) error {
	form := url.Values{
		"grant_type": {"client_credentials"}, "nfInstanceId": {r.instanceID},
		"nfType": {"UPF"}, "targetNfType": {"NRF"}, "scope": {"nnrf-nfm"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.nrfRoot+nrfTokenPath,
		strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rsp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := rsp.Body.Close(); closeErr != nil {
			r.logger.Debugf("nrf token: close body: %v", closeErr)
		}
	}()
	if rsp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", rsp.StatusCode)
	}
	var token struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(rsp.Body, 1<<20)).Decode(&token); err != nil {
		return err
	}
	if token.AccessToken == "" {
		return errors.New("empty access_token")
	}
	lifetime := time.Duration(token.ExpiresIn) * time.Second
	if lifetime <= 0 {
		lifetime = time.Minute
	}
	r.mu.Lock()
	r.token = token.AccessToken
	// Refresh slightly early so a token does not expire in flight.
	r.tokenExpiry = time.Now().Add(lifetime * 9 / 10)
	r.mu.Unlock()
	return nil
}

// newUUIDv4 returns a random RFC 9562 version 4 UUID (NfInstanceId format).
func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
