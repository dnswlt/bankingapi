package comdirect

// https://www.comdirect.de/cms/media/comdirect_REST_API_Dokumentation.pdf
// https://kunde.comdirect.de/cms/media/comdirect_rest_api_swagger.json

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Credentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Username     string `json:"username"`
	Password     string `json:"password"`
}

type OAuthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	Kdnr         string `json:"kdnr"`
	Bpid         int64  `json:"bpid"`
	KontaktID    int64  `json:"kontaktId"`
}

type ClientRequestIDHeader struct {
	ClientRequestID ClientRequestID `json:"clientRequestId"`
}

type ClientRequestID struct {
	SessionID string `json:"sessionId"`
	RequestID string `json:"requestId"`
}

type XOnceAuthenticationInfo struct {
	ID             string   `json:"id"`
	Typ            string   `json:"typ,omitempty"`
	Challenge      string   `json:"challenge,omitempty"`
	AvailableTypes []string `json:"availableTypes,omitempty"`
}

type XHTTPResponseInfoMessage struct {
	Severity string         `json:"severity"`
	Key      string         `json:"key"`
	Message  string         `json:"message"`
	Args     map[string]any `json:"args"`
	Origin   string         `json:"origin"`
}

type XHTTPResponseInfo struct {
	Messages []*XHTTPResponseInfoMessage `json:"messages"`
}

type SessionTANInfo struct {
	session  *Session
	authInfo *XOnceAuthenticationInfo
}

// OAuthToken contains the tokens relevant for authentication in
// REST requests to the API, and their expiry time.
type OAuthToken struct {
	AccessToken  string    `json:"accessToken"`
	RefreshToken string    `json:"refreshToken"`
	ExpireTime   time.Time `json:"expireTime"`
}

type Client struct {
	credentials     Credentials
	oAuthToken      OAuthToken
	clientSessionID string // Session ID created by the client, used in the x-http-request-info header
	client          *http.Client
}

const (
	// URL prefix for all REST APIs.
	URLPrefix = "https://api.comdirect.de/api"

	// URLs for OAuth flows.
	OAuthTokenURL       = "https://api.comdirect.de/oauth/token"
	OAuthTokenRevokeURL = "https://api.comdirect.de/oauth/revoke"
)

// Error returns the error messages contained in x concatenated as a single
// (potentially multi-line) string.
func (x XHTTPResponseInfo) Error() string {
	var sb strings.Builder
	for i, m := range x.Messages {
		if i > 0 {
			sb.WriteRune('\n')
		}
		s := fmt.Sprintf("%s (%s): %s", m.Severity, m.Key, m.Message)
		sb.WriteString(s)
	}
	return sb.String()
}

func (t *OAuthTokenResponse) OAuthToken(now time.Time) OAuthToken {
	return OAuthToken{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		ExpireTime:   now.Add(time.Duration(t.ExpiresIn) * time.Second),
	}
}

// LoadCredentials tries to read Credentials as JSON from the given file.
func LoadCredentials(filePath string) (Credentials, error) {
	var cred Credentials
	f, err := os.Open(filePath)
	if err != nil {
		return Credentials{}, fmt.Errorf("failed to open credentials file: %v", err)
	}
	defer f.Close()
	err = json.NewDecoder(f).Decode(&cred)
	if err != nil {
		return Credentials{}, fmt.Errorf("failed to read credentials file: %v", err)
	}
	return cred, nil
}

// LoadOAuthToken tries to read an OAuthToken as JSON from the given file, if that file exists.
// If the file does not exist, forwards the os.ErrNotExist error from os.Open.
func LoadOAuthToken(filePath string) (*OAuthToken, error) {
	var token OAuthToken

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if err := json.NewDecoder(file).Decode(&token); err != nil {
		return nil, err
	}

	return &token, nil
}

// SaveOAuthToken saves the given token as JSON to filePath.
func SaveOAuthToken(filePath string, token OAuthToken) error {
	f, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("Failed to create OAuth token file: %v", err)
	}
	defer f.Close()

	err = json.NewEncoder(f).Encode(token)
	if err != nil {
		return fmt.Errorf("Failed to save OAuth token: %v", err)
	}
	return nil
}

// Generates a hexadecimal session ID of the given length, using lower-case letters.
// Example for length == 16: "1234567890abcdef"
func generateClientSessionID(length int) string {
	if length <= 0 {
		return ""
	}

	// Each byte produces 2 hex characters, so we need (length+1)/2 bytes
	numBytes := (length + 1) / 2
	buf := make([]byte, numBytes)
	_, err := rand.Read(buf)
	if err != nil {
		panic("failed to generate random bytes: " + err.Error())
	}

	hexStr := hex.EncodeToString(buf)
	return hexStr[:length] // trim to exact length
}

func NewClient(cred Credentials, token *OAuthToken) *Client {
	var oAuthToken OAuthToken
	if token != nil {
		oAuthToken = *token
	}
	return &Client{
		credentials:     cred,
		client:          &http.Client{},
		clientSessionID: generateClientSessionID(32),
		oAuthToken:      oAuthToken,
	}
}

func (c *Client) SessionID() string {
	return c.clientSessionID
}

func (c *Client) OAuthToken() OAuthToken {
	return c.oAuthToken
}

func urlPath(path string) string {
	path = strings.TrimPrefix(path, "/")
	return fmt.Sprintf("%s/%s", URLPrefix, path)
}

func xHTTPResponseInfo(h http.Header) (XHTTPResponseInfo, error) {
	respInfo := h.Get("x-http-response-info")
	if respInfo == "" {
		return XHTTPResponseInfo{}, nil
	}
	var result XHTTPResponseInfo
	err := json.Unmarshal([]byte(respInfo), &result)
	if err != nil {
		return XHTTPResponseInfo{}, fmt.Errorf("Could not parse x-http-response-info as JSON: %v", respInfo)
	}
	return result, nil
}

func (c *Client) addAuthorizationHeader(req *http.Request) {
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.oAuthToken.AccessToken))
}

func (c *Client) addRequestInfoHeader(req *http.Request) {
	now := time.Now()
	// Must be 9 digits. We are using HHMMSSsss.
	requestID := now.Format("150405") + fmt.Sprintf("%03d", now.Nanosecond()/1e6)

	bs, err := json.Marshal(ClientRequestIDHeader{
		ClientRequestID: ClientRequestID{
			SessionID: c.clientSessionID,
			RequestID: requestID,
		},
	})
	if err != nil {
		log.Fatalf("Cannot marshal clientRequestID: %v", err)
	}
	req.Header.Set("x-http-request-info", string(bs))
}

func decodeAndDrain[T any](resp *http.Response) (T, error) {
	var result T
	err := json.NewDecoder(resp.Body).Decode(&result)
	_, _ = io.Copy(io.Discard, resp.Body)
	if err != nil {
		var zero T
		return zero, err
	}
	return result, nil
}

func (c *Client) FetchToken() error {
	cred := c.credentials
	form := url.Values{}
	form.Set("client_id", cred.ClientID)
	form.Set("client_secret", cred.ClientSecret)
	form.Set("grant_type", "password")
	form.Set("username", cred.Username)
	form.Set("password", cred.Password)

	req, err := http.NewRequest("POST", OAuthTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("HTTP error for %s: %s", req.URL.String(), resp.Status)
	}

	result, err := decodeAndDrain[OAuthTokenResponse](resp)
	if err != nil {
		return err
	}

	c.oAuthToken = result.OAuthToken(time.Now())
	return nil
}

func (c *Client) execCDSecondaryFlow() error {
	form := url.Values{}
	form.Set("client_id", c.credentials.ClientID)
	form.Set("client_secret", c.credentials.ClientSecret)
	form.Set("grant_type", "cd_secondary")
	form.Set("token", c.oAuthToken.AccessToken)

	req, err := http.NewRequest("POST", OAuthTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("request for %s failed: %v", req.URL.String(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("HTTP error for %s: %s", req.URL.String(), resp.Status)
	}
	result, err := decodeAndDrain[OAuthTokenResponse](resp)
	if err != nil {
		return err
	}
	c.oAuthToken = result.OAuthToken(time.Now())
	return nil
}

func (c *Client) RefreshToken() error {
	form := url.Values{}
	form.Set("client_id", c.credentials.ClientID)
	form.Set("client_secret", c.credentials.ClientSecret)
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", c.oAuthToken.RefreshToken)

	req, err := http.NewRequest("POST", OAuthTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("request for %s failed: %v", req.URL.String(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("HTTP error for %s: %s", req.URL.String(), resp.Status)
	}
	result, err := decodeAndDrain[OAuthTokenResponse](resp)
	if err != nil {
		return err
	}
	c.oAuthToken = result.OAuthToken(time.Now())
	return nil
}

func (c *Client) RevokeToken() error {
	req, err := http.NewRequest("DELETE", OAuthTokenRevokeURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	c.addAuthorizationHeader(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP error for %s: %s", req.URL.String(), resp.Status)
	}
	return nil
}

func (c *Client) fetchSession() (*Session, error) {
	req, err := http.NewRequest("GET", urlPath("/session/clients/user/v1/sessions"), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Accept", "application/json")
	c.addAuthorizationHeader(req)
	c.addRequestInfoHeader(req) // x-http-request-info

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request for %s failed: %v", req.URL.String(), err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		_, _ = io.Copy(io.Discard, resp.Body)
		respInfo, _ := xHTTPResponseInfo(resp.Header)
		return nil, fmt.Errorf("HTTP error %s for %s: %s", resp.Status, req.URL.String(), respInfo.Error())
	}

	sessions, err := decodeAndDrain[[]*Session](resp)
	if err != nil {
		return nil, fmt.Errorf("failed to read JSON response: %v", err)
	}
	if len(sessions) == 0 {
		return nil, fmt.Errorf("response did not contain any sessions")
	}
	if len(sessions) > 1 {
		return nil, fmt.Errorf("response contained %d sessions", len(sessions))
	}
	return sessions[0], nil
}

func (c *Client) fetchAuthInfo(session *Session) (*XOnceAuthenticationInfo, error) {
	session.SetActivated2FA(true)
	session.SetSessionTanActive(true)
	jsonSession, err := json.Marshal(session)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Session: %v", err)
	}
	req, err := http.NewRequest("POST",
		urlPath(fmt.Sprintf("/session/clients/user/v1/sessions/%s/validate", session.GetIdentifier())),
		bytes.NewBuffer(jsonSession))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	c.addAuthorizationHeader(req)
	c.addRequestInfoHeader(req) // x-http-request-info

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request for %s failed: %v", req.URL.String(), err)
	}
	defer resp.Body.Close()
	// Returns the same Session, so we don't care about the response body.
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 400 {
		respInfo, _ := xHTTPResponseInfo(resp.Header)
		return nil, fmt.Errorf("HTTP error %s for %s: %s", resp.Status, req.URL.String(), respInfo.Error())
	}

	var authInfo XOnceAuthenticationInfo
	authInfoStr := resp.Header.Get("x-once-authentication-info")
	if err := json.Unmarshal([]byte(authInfoStr), &authInfo); err != nil {
		return nil, fmt.Errorf("failed to parse x-once-authentication-info header: %s: %s", authInfoStr, err)
	}

	return &authInfo, nil
}

func (c *Client) RequestSessionTAN() (*SessionTANInfo, error) {
	if c.oAuthToken.AccessToken == "" {
		return nil, fmt.Errorf("no access token (forgot to call FetchToken first?)")
	}

	session, err := c.fetchSession()
	if err != nil {
		return nil, err
	}
	authInfo, err := c.fetchAuthInfo(session)
	if err != nil {
		return nil, err
	}
	return &SessionTANInfo{
		session:  session,
		authInfo: authInfo,
	}, nil
}

func (c *Client) patchSession(tan string, info *SessionTANInfo) error {
	jsonSession, err := json.Marshal(info.session)
	if err != nil {
		return fmt.Errorf("cannot marshal session: %v", err)
	}
	req, err := http.NewRequest("PATCH",
		urlPath(fmt.Sprintf("/session/clients/user/v1/sessions/%s", info.session.GetIdentifier())),
		bytes.NewBuffer(jsonSession))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	c.addAuthorizationHeader(req)
	c.addRequestInfoHeader(req) // x-http-request-info
	jsonAuthInfo, err := json.Marshal(XOnceAuthenticationInfo{ID: info.authInfo.ID})
	if err != nil {
		return fmt.Errorf("failed to marshal XOnceAuthenticationInfo: %v", err)
	}
	req.Header.Set("x-once-authentication-info", string(jsonAuthInfo))
	if tan != "" {
		req.Header.Set("x-once-authentication", tan)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("request for %s failed: %v", req.URL.String(), err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 400 {
		respInfo, _ := xHTTPResponseInfo(resp.Header)
		return fmt.Errorf("HTTP error %s for %s: %s", resp.Status, req.URL.String(), respInfo.Error())
	}
	return nil
}

func (c *Client) ActivateSessionTAN(tan string, info *SessionTANInfo) error {
	err := c.patchSession(tan, info)
	if err != nil {
		return err
	}
	return c.execCDSecondaryFlow()
}

func getResource[T any](c *Client, pathSuffix string) (*T, error) {
	req, err := http.NewRequest("GET", urlPath(pathSuffix), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	c.addAuthorizationHeader(req)
	c.addRequestInfoHeader(req) // x-http-request-info
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request for %s failed: %v", req.URL.String(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP error for %s: %s", req.URL.String(), resp.Status)
	}

	var result T
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %v", err)
	}
	return &result, nil
}

func (c *Client) ListAccountBalances() ([]AccountBalance, error) {
	result, err := getResource[ListResourceAccountBalance](
		c, "/banking/clients/user/v2/accounts/balances")
	if err != nil {
		return nil, fmt.Errorf("failed to get account balances: %v", err)
	}
	return result.GetValues(), nil
}

func (c *Client) ListAccountTransactions(accountID string) ([]AccountTransaction, error) {
	result, err := getResource[ListResourceAccountTransaction](
		c, fmt.Sprintf("/banking/v1/accounts/%s/transactions", accountID))
	if err != nil {
		return nil, fmt.Errorf("failed to get account transactions: %v", err)
	}
	return result.GetValues(), nil
}

func (c *Client) ListDepots() ([]Depot, error) {
	result, err := getResource[ListResourceDepot](
		c, "/brokerage/clients/user/v3/depots")
	if err != nil {
		return nil, fmt.Errorf("failed to get depots: %v", err)
	}
	return result.GetValues(), nil
}

func (c *Client) GetDepotPositions(depotID string) ([]DepotPosition, error) {
	query := url.Values{}
	// Include "instrument" data, e.g. the ISIN.
	query.Set("with-attr", "instrument")

	result, err := getResource[ListResourceDepotPosition](
		c, fmt.Sprintf("/brokerage/v3/depots/%s/positions?%s", depotID, query.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to get depot positions: %v", err)
	}
	return result.GetValues(), nil
}
