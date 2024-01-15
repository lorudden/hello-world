package tokens

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

type PhantomTokenExchange interface {
	Middleware() func(http.Handler) http.Handler
	InstallChiHandlers(r *chi.Mux)
	Shutdown()
}

type cookieValue struct {
	SessionID string `json:"session"`
	SourceIP  string `json:"ip"`
}

type phantomTokens struct {
	logger *slog.Logger

	appRoot string

	configURL    string
	clientID     string
	clientSecret string

	loginEndpoint  string
	logoutEndpoint string

	logoutRedirectURL string

	cookieName string

	secretKey []byte

	provider           *oidc.Provider
	oauth2Config       oauth2.Config
	insecureSkipVerify bool
	parEndpoint        string
	endSessionEndpoint string

	sessions map[string]*session
	mu       sync.Mutex
}

func (pt *phantomTokens) InstallChiHandlers(r *chi.Mux) {
	r.Get(pt.loginEndpoint, pt.LoginHandler())
	r.Get(pt.loginEndpoint+"/{id}", pt.LoginExchangeHandler())
	r.Get(pt.logoutEndpoint, pt.LogoutHandler())
}

func WithAppRoot(appRoot string) func(*phantomTokens) {
	return func(pt *phantomTokens) {
		if strings.HasSuffix(appRoot, "/") {
			appRoot = appRoot[0 : len(appRoot)-1]
		}
		pt.appRoot = appRoot
	}
}

func WithCookieName(name string) func(*phantomTokens) {
	return func(pt *phantomTokens) {
		// Prepend the cookie name with __Host- to create a "domain locked" cookie.
		// See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#__host-
		pt.cookieName = fmt.Sprintf("__Host-%s", name)
	}
}

func WithInsecureSkipVerify() func(*phantomTokens) {
	return func(pt *phantomTokens) {
		pt.insecureSkipVerify = true
	}
}

func WithLogger(logger *slog.Logger) func(*phantomTokens) {
	return func(pt *phantomTokens) {
		pt.logger = logger
	}
}

func WithLoginLogoutEndpoints(loginEndpoint, logoutEndpoint string) func(*phantomTokens) {
	mustBeNonEmptyAndNotEndWithSlash := func(ep string) {
		if len(ep) == 0 {
			panic("endpoint must not be empty")
		}

		if strings.HasSuffix(ep, "/") {
			panic("endpoint must not end with a slash")
		}
	}

	return func(pt *phantomTokens) {
		mustBeNonEmptyAndNotEndWithSlash(loginEndpoint)
		mustBeNonEmptyAndNotEndWithSlash(logoutEndpoint)

		pt.loginEndpoint = loginEndpoint
		pt.logoutEndpoint = logoutEndpoint
	}
}

func WithProvider(configURL, clientID, clientSecret string) func(*phantomTokens) {
	return func(pt *phantomTokens) {
		pt.configURL = configURL
		pt.clientID = clientID
		pt.clientSecret = clientSecret
	}
}

func WithSecretKey(key []byte) func(*phantomTokens) {
	return func(pt *phantomTokens) {
		if len(key) != 32 {
			panic("aes key size must be 32 bytes")
		}
		pt.secretKey = key
	}
}

func NewPhantomTokenExchange(opts ...func(*phantomTokens)) (PhantomTokenExchange, error) {

	defaults := []func(*phantomTokens){
		WithCookieName("id"),
		WithLoginLogoutEndpoints("/login", "/logout"),
	}

	pt := &phantomTokens{
		sessions: map[string]*session{},
	}

	opts = append(defaults, opts...)

	for _, opt := range opts {
		opt(pt)
	}

	if len(pt.secretKey) == 0 {
		// Create a random secret if none provided in opts
		secretKey := make([]byte, 32)
		_, err := io.ReadFull(rand.Reader, secretKey)
		if err != nil {
			return nil, err
		}
		WithSecretKey(secretKey)(pt)
	}

	go func(ctx context.Context) {
		provider, err := oidc.NewProvider(ctx, pt.configURL)
		for err != nil {
			pt.logger.Info("failed to connect to oidc provider", "err", err.Error())
			time.Sleep(2 * time.Second)
			provider, err = oidc.NewProvider(ctx, pt.configURL)
		}

		c := struct {
			EndpointPAR        string `json:"pushed_authorization_request_endpoint"`
			EndpointEndSession string `json:"end_session_endpoint"`
		}{}

		if provider.Claims(&c) == nil {
			pt.parEndpoint = c.EndpointPAR
			pt.endSessionEndpoint = c.EndpointEndSession

			if pt.parEndpoint != "" {
				pt.logger.Info("PAR endpoint found at " + c.EndpointPAR)
			}
		}

		pt.provider = provider
		pt.oauth2Config = oauth2.Config{
			ClientID:     pt.clientID,
			ClientSecret: pt.clientSecret,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		}
	}(pt.providerClientContext(context.Background()))

	return pt, nil
}

func (pt *phantomTokens) Shutdown() {}

func (pt *phantomTokens) providerClientContext(ctx context.Context) context.Context {
	if pt.insecureSkipVerify {
		pt.logger.Warn("!!! - PROVIDER CERTIFICATE VERIFICATION DISABLED - !!!")

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}
		ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	}

	return ctx
}

func (pt *phantomTokens) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			cookie, err := pt.getCookie(w, r)

			if err == nil {
				tokenChan, err := pt.sessionToken(r.Context(), cookie.SessionID)
				var token *oauth2.Token
				if err == nil {
					token = <-tokenChan
				}

				if err == nil && token == nil {
					err = errors.New("sessionToken returned nil token")
				}

				if err != nil {
					pt.logger.Error("failed to lookup access token", "err", err.Error(), "session", cookie.SessionID)
					pt.clearCookie(w)
					pt.clearSession(cookie.SessionID)
				} else if token != nil {
					r.Header.Add("Authorization", token.TokenType+" "+token.AccessToken)
				}
			}

			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}

func (pt *phantomTokens) clearCookie(w http.ResponseWriter) {
	cookie := http.Cookie{
		Name:     pt.cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}

	pt.logger.Debug("clearing session cookie from browser")
	http.SetCookie(w, &cookie)
}

func (pt *phantomTokens) getCookie(w http.ResponseWriter, r *http.Request) (*cookieValue, error) {
	cookie, err := r.Cookie(pt.cookieName)
	if err != nil {
		return nil, err
	}

	encryptedValue, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		pt.clearCookie(w)
		return nil, fmt.Errorf("decoding failed: %w", err)
	}

	// Create a new AES cipher block from the secret key.
	block, err := aes.NewCipher(pt.secretKey)
	if err != nil {
		pt.logger.Error("cipher failure", "err", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return nil, fmt.Errorf("cipher failure: %w", err)
	}

	// Wrap the cipher block in Galois Counter Mode.
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		pt.logger.Error("cipher failure", "err", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return nil, fmt.Errorf("cipher failure: %w", err)
	}

	// Get the nonce size.
	nonceSize := aesGCM.NonceSize()

	// To avoid a potential 'index out of range' panic in the next step, we
	// check that the length of the encrypted value is at least the nonce size.
	if len(encryptedValue) < nonceSize {
		err = errors.New("encrypted value too short")
		pt.logger.Error(err.Error(), "length", len(encryptedValue))
		pt.clearCookie(w)
		w.WriteHeader(http.StatusBadRequest)
		return nil, err
	}

	// Split apart the nonce from the actual encrypted data.
	nonce := encryptedValue[:nonceSize]
	ciphertext := encryptedValue[nonceSize:]

	// Use aesGCM.Open() to decrypt and authenticate the data.
	plaintext, err := aesGCM.Open(nil, []byte(nonce), []byte(ciphertext), nil)
	if err != nil {
		pt.logger.Error("failed to decrypt and authenticate cookie data", "err", err.Error())
		pt.clearCookie(w)
		w.WriteHeader(http.StatusBadRequest)
		return nil, err
	}

	value := &cookieValue{}
	err = json.Unmarshal(plaintext, &value)
	if err != nil {
		pt.logger.Error("cookie contents error", "err", err.Error())
		pt.clearCookie(w)
		w.WriteHeader(http.StatusBadRequest)
		return nil, fmt.Errorf("cookie contents error: %w", err)
	}

	if value.SourceIP != "" && value.SourceIP != r.Header.Get("X-Real-IP") {
		pt.logger.Error("session ip address changed", "old", value.SourceIP, "new", r.Header.Get("X-Real-IP"), "session", value.SessionID)
		pt.clearCookie(w)
		w.WriteHeader(http.StatusBadRequest)
		return nil, errors.New("session ip address changed")
	}

	return value, nil
}

func (pt *phantomTokens) newCookie(value cookieValue) (*http.Cookie, error) {

	// Set httponly, secure and strict samesite mode for our cookies
	// See https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies
	cookie := http.Cookie{
		Name:     pt.cookieName,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}

	// Create a new AES cipher block from the secret key.
	block, err := aes.NewCipher(pt.secretKey)
	if err != nil {
		return nil, err
	}

	// Wrap the cipher block in Galois Counter Mode.
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Create a unique nonce containing 12 random bytes.
	nonce := make([]byte, aesGCM.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	marshalledBytes, _ := json.Marshal(value)

	// Encrypt the data using aesGCM.Seal(). By passing the nonce as the first
	// parameter, the encrypted data will be appended to the nonce — meaning
	// that the returned encryptedValue variable will be in the format
	// "{nonce}{encrypted plaintext data}".
	encryptedValue := aesGCM.Seal(nonce, nonce, marshalledBytes, nil)

	// Encode the encrypted cookie value using base64.
	cookie.Value = base64.URLEncoding.EncodeToString(encryptedValue)

	return &cookie, nil
}

type tokenState int

const (
	NONE       tokenState = 0
	REFRESHING tokenState = 1
	ACTIVE     tokenState = 2
)

type session struct {
	ID           string
	LoginState   string
	PKCEVerifier string

	IDToken    string
	Token      *oauth2.Token
	TokenState tokenState
	TokenQueue []chan (*oauth2.Token)
}

func (pt *phantomTokens) clearSession(sessionID string) *session {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	s, ok := pt.sessions[sessionID]
	if !ok {
		return nil
	}

	pt.logger.Info("clearing session from memory", "session", sessionID)

	// Release any blocked requests that are waiting for a token refresh
	if len(s.TokenQueue) > 0 {
		pt.logger.Warn("clearing session with pending token requests", "count", len(s.TokenQueue), "session", sessionID)
		for _, consumer := range s.TokenQueue {
			consumer <- nil
		}
		s.TokenQueue = []chan (*oauth2.Token){}
	}

	delete(pt.sessions, sessionID)
	return s
}

func (pt *phantomTokens) newSession() *session {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	s := &session{
		ID:           uuid.NewString(),
		LoginState:   uuid.NewString(),
		PKCEVerifier: oauth2.GenerateVerifier(),
		TokenQueue:   []chan (*oauth2.Token){},
	}
	pt.sessions[s.ID] = s
	return s
}

var ErrNoSuchSession error = errors.New("no such session")
var ErrNoToken error = errors.New("session has no token")
var ErrRefreshTokenExpired error = errors.New("refresh token expired")

func (pt *phantomTokens) sessionLoginState(ctx context.Context, sessionID string) (string, error) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	s, ok := pt.sessions[sessionID]
	if !ok {
		return "", ErrNoSuchSession
	}

	return s.LoginState, nil
}

func (pt *phantomTokens) sessionPKCEVerifier(ctx context.Context, sessionID string) (string, error) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	s, ok := pt.sessions[sessionID]
	if !ok {
		return "", ErrNoSuchSession
	}

	return s.PKCEVerifier, nil
}

func (pt *phantomTokens) sessionHasToken(ctx context.Context, sessionID string) bool {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	s, ok := pt.sessions[sessionID]
	if ok && s.TokenState != NONE {
		return true
	}

	return false
}

func (pt *phantomTokens) sessionToken(ctx context.Context, sessionID string) (chan (*oauth2.Token), error) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	s, ok := pt.sessions[sessionID]
	if !ok {
		return nil, ErrNoSuchSession
	}

	if s.Token == nil {
		return nil, ErrNoToken
	}

	result := make(chan (*oauth2.Token), 1)

	if s.Token.Valid() {
		result <- s.Token
	} else {
		s.TokenQueue = append(s.TokenQueue, result)

		if s.TokenState == ACTIVE {
			s.TokenState = REFRESHING
			pt.logger.Info("initiating token refresh", "session", sessionID)

			go func(t *oauth2.Token) {
				ctx := pt.providerClientContext(context.WithoutCancel(ctx))
				tokenSource := pt.oauth2Config.TokenSource(ctx, t)
				t, err := tokenSource.Token()

				if err != nil {
					pt.logger.Error("failed to refresh token", "err", err.Error(), "session", sessionID)
					t = nil
				}

				pt.sessionTokens(ctx, sessionID, s.IDToken, t)
			}(s.Token)
		} else {
			pt.logger.Info("queuing token request due to pending refresh", "session", sessionID)
		}
	}

	return result, nil
}

func (pt *phantomTokens) sessionTokens(ctx context.Context, sessionID, idToken string, token *oauth2.Token) error {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	s, ok := pt.sessions[sessionID]
	if !ok {
		return ErrNoSuchSession
	}

	s.IDToken = idToken
	s.Token = token
	s.TokenState = ACTIVE

	if len(s.TokenQueue) > 0 {
		pt.logger.Info("sending refreshed token to blocked consumers", "count", len(s.TokenQueue), "session", sessionID)

		for _, consumer := range s.TokenQueue {
			consumer <- token
		}
		s.TokenQueue = []chan (*oauth2.Token){}
	}

	return nil
}

func (pt *phantomTokens) LoginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s := pt.newSession()

		par := url.Values{}
		par.Add("response_type", "code")
		par.Add("client_id", pt.clientID)
		par.Add("scope", strings.Join(pt.oauth2Config.Scopes, " "))
		par.Add("state", s.LoginState)
		par.Add("code_challenge_method", "S256")
		par.Add("code_challenge", oauth2.S256ChallengeFromVerifier(s.PKCEVerifier))
		par.Add("redirect_uri", pt.appRoot+pt.loginEndpoint+"/"+s.ID)

		postReq, _ := http.NewRequest(http.MethodPost, pt.parEndpoint, strings.NewReader(par.Encode()))
		postReq.SetBasicAuth(url.QueryEscape(pt.clientID), url.QueryEscape(pt.clientSecret))
		postReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		client := http.DefaultClient

		if pt.insecureSkipVerify {
			client = &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
			}
		}

		resp, err := client.Do(postReq)
		if err != nil {
			pt.logger.Error("par endpoint failure", "err", err.Error(), "session", s.ID)
			pt.clearSession(s.ID)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		respJson, _ := io.ReadAll(resp.Body)

		requestObject := struct {
			URI              string `json:"request_uri"`
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}{}
		err = json.Unmarshal(respJson, &requestObject)

		if resp.StatusCode >= http.StatusBadRequest {
			pt.logger.Error("par error", "code", resp.StatusCode, "error", requestObject.Error, "description", requestObject.ErrorDescription, "session", s.ID)
			pt.clearSession(s.ID)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if resp.StatusCode != http.StatusCreated {
			pt.logger.Error("invalid response from par endoint", "code", resp.StatusCode, "session", s.ID)
			pt.clearSession(s.ID)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r,
			fmt.Sprintf("%s?client_id=%s&request_uri=%s",
				pt.oauth2Config.Endpoint.AuthURL,
				pt.clientID,
				url.QueryEscape(requestObject.URI),
			),
			http.StatusFound,
		)
		return
	}
}

func (pt *phantomTokens) LoginExchangeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		ctx := pt.providerClientContext(r.Context())

		// TODO: wait until https://github.com/golang/go/issues/61410 ships
		urlParts := strings.Split(r.URL.Path, "/")
		sessionID := urlParts[len(urlParts)-1]
		loginState, err1 := pt.sessionLoginState(ctx, sessionID)
		pkceVerifier, err2 := pt.sessionPKCEVerifier(ctx, sessionID)

		if err1 != nil || err2 != nil {
			pt.logger.Warn("attempt to login with invalid session id")
			w.WriteHeader(http.StatusNotFound)
			return
		}

		if pt.sessionHasToken(ctx, sessionID) {
			pt.logger.Warn("possibly malicious call: this session has already exchanged token", "session", sessionID)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		var err error
		defer func() {
			if err != nil {
				pt.clearSession(sessionID)
			}
		}()

		state := r.URL.Query().Get("state")
		if state != loginState {
			err = errors.New("state parameter does not match")
			pt.logger.Warn("suspicious login attempt", "session", sessionID, "err", err.Error())
			w.WriteHeader(http.StatusNotFound)
			return
		}

		exchange := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {r.URL.Query().Get("code")},
			"code_verifier": {pkceVerifier},
			"redirect_uri":  {pt.appRoot + pt.loginEndpoint + "/" + sessionID},
		}

		postReq, _ := http.NewRequest(http.MethodPost, pt.oauth2Config.Endpoint.TokenURL, strings.NewReader(exchange.Encode()))
		postReq.SetBasicAuth(url.QueryEscape(pt.clientID), url.QueryEscape(pt.clientSecret))
		postReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		client := http.DefaultClient

		if pt.insecureSkipVerify {
			client = &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
			}
		}

		exchangeResponse, err := client.Do(postReq)

		if err != nil {
			pt.logger.Error("failed to exchange token", "err", err.Error(), "session", sessionID)
			http.Error(w, "failed to exchange token", http.StatusInternalServerError)
			return
		}
		defer exchangeResponse.Body.Close()

		if exchangeResponse.StatusCode != http.StatusOK {
			err = fmt.Errorf("invalid status code")
			pt.logger.Error("token server error", "code", exchangeResponse.StatusCode, "session", sessionID)
			http.Error(w, "invalid status code from token server", http.StatusInternalServerError)
			return
		}

		body, _ := io.ReadAll(exchangeResponse.Body)

		oauth2Token := &oauth2.Token{}
		err = json.Unmarshal(body, &oauth2Token)
		if err != nil {
			pt.logger.Error("failed to unmarshal token", "err", err.Error(), "session", sessionID)
			http.Error(w, "failed to unmarshal token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		pt.logger.Info("token response", "body", string(body), "session", sessionID)

		extra := &struct {
			IDToken          string `json:"id_token"`
			ExpiresIn        int32  `json:"expires_in"`
			RefreshExpiresIn int32  `json:"refresh_expires_in"`
		}{}
		err = json.Unmarshal(body, extra)
		if err != nil || extra.IDToken == "" {
			http.Error(w, "no id_token field in oauth2 token.", http.StatusInternalServerError)
			return
		}

		oauth2Token.Expiry = time.Now().Add(time.Duration(extra.ExpiresIn) * time.Second)
		pt.logger.Info("token expiry", "when", oauth2Token.Expiry.Format(time.RFC3339), "session", sessionID)

		verifier := pt.provider.Verifier(&oidc.Config{ClientID: pt.clientID})
		_, err = verifier.Verify(ctx, extra.IDToken)
		if err != nil {
			http.Error(w, "failed to verify id token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		pt.sessionTokens(ctx, sessionID, extra.IDToken, oauth2Token)

		var newCookie *http.Cookie
		newCookie, err = pt.newCookie(cookieValue{
			SessionID: sessionID,
			SourceIP:  r.Header.Get("X-Real-IP"),
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, newCookie)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func (pt *phantomTokens) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := pt.getCookie(w, r)
		if err != nil {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		pt.clearCookie(w)
		s := pt.clearSession(cookie.SessionID)

		if s != nil && s.Token.Valid() {
			logoutURL := pt.endSessionEndpoint + "?id_token_hint=" + s.IDToken + "&post_logout_redirect_uri="
			logoutURL += url.QueryEscape(pt.appRoot)

			http.Redirect(w, r, logoutURL, http.StatusFound)
			return
		}

		http.Redirect(w, r, "/", http.StatusFound)
	}
}
