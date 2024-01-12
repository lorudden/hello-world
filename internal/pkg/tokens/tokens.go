package tokens

import (
	"bytes"
	"compress/gzip"
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
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

type PhantomTokenExchange interface {
	Middleware() func(http.Handler) http.Handler

	LoginHandler() http.HandlerFunc
	LogoutHandler() http.HandlerFunc
}

type cookieValue struct {
	LoginState     string `json:"state"`
	LoginValidator string `json:"validator"`

	SessionID string `json:"session"`
	SourceIP  string `json:"ip"`

	Token   *oauth2.Token `json:"token"`
	IdToken string
}

type phantomTokens struct {
	logger *slog.Logger

	configURL    string
	clientID     string
	clientSecret string

	cookieName string

	secretKey []byte

	provider           *oidc.Provider
	oauth2Config       oauth2.Config
	insecureSkipVerify bool
}

func WithCookieName(name string) func(*phantomTokens) {
	return func(pt *phantomTokens) {
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

	pt := &phantomTokens{}

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

	if pt.cookieName == "" {
		WithCookieName("id")(pt)
	}

	go func(ctx context.Context) {
		provider, err := oidc.NewProvider(ctx, pt.configURL)
		for err != nil {
			pt.logger.Info("failed to connect to oidc provider", "err", err.Error())
			time.Sleep(1 * time.Second)
			provider, err = oidc.NewProvider(ctx, pt.configURL)
		}

		pt.provider = provider
		pt.oauth2Config = oauth2.Config{
			ClientID:     pt.clientID,
			ClientSecret: pt.clientSecret,
			RedirectURL:  "https://xn--lrudden-90a.local:8443/login",
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		}
	}(pt.providerClientContext(context.Background()))

	return pt, nil
}

type cookieValueKeyType string

const cookieValueKey cookieValueKeyType = "id-cookie"

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
				ctx := context.WithValue(r.Context(), cookieValueKey, cookie)
				r = r.WithContext(ctx)

				if cookie.Token != nil {
					if !cookie.Token.Valid() {
						tokenSource := pt.oauth2Config.TokenSource(pt.providerClientContext(r.Context()), cookie.Token)
						newToken, err := tokenSource.Token()
						if err != nil {
							pt.logger.Error("token source failure", "err", err.Error())
							pt.clearCookie(w)
						} else if !newToken.Valid() {
							pt.logger.Info("refresh token expired and a relogin is required", "session", cookie.SessionID)
							pt.clearCookie(w)
						} else {
							cookie.Token = newToken
							c, _ := pt.newCookie(*cookie)
							http.SetCookie(w, c)
						}
					}

					if cookie.Token.Valid() {
						r.Header.Add(
							"Authorization",
							cookie.Token.Type()+" "+cookie.Token.AccessToken,
						)
					}
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
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, &cookie)

	w.Header().Add("HX-Redirect", "/")
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

	// Use aesGCM.Open() to decrypt and authenticate the data. If this fails,
	// return a ErrInvalidValue error.
	plaintext, err := aesGCM.Open(nil, []byte(nonce), []byte(ciphertext), nil)
	if err != nil {
		pt.logger.Error("aes gcm error", "err", err.Error())
		pt.clearCookie(w)
		w.WriteHeader(http.StatusBadRequest)
		return nil, err
	}

	zr, err := gzip.NewReader(bytes.NewReader(plaintext))
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	plaintext, err = io.ReadAll(zr)
	if err != nil {
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
		pt.logger.Error("session ip address changed", "old", value.SourceIP, "new", r.Header.Get("X-Real-IP"))
		pt.clearCookie(w)
		w.WriteHeader(http.StatusBadRequest)
		return nil, errors.New("session ip address changed")
	}

	// cookie was found
	pt.logger.Info("cookie found", "value", string(plaintext))

	return value, nil
}

func (pt *phantomTokens) newCookie(value cookieValue) (*http.Cookie, error) {

	cookie := http.Cookie{
		Name:     pt.cookieName,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
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

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err = zw.Write(marshalledBytes)
	if err != nil {
		return nil, err
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}

	// Encrypt the data using aesGCM.Seal(). By passing the nonce as the first
	// parameter, the encrypted data will be appended to the nonce — meaning
	// that the returned encryptedValue variable will be in the format
	// "{nonce}{encrypted plaintext data}".
	encryptedValue := aesGCM.Seal(nonce, nonce, buf.Bytes(), nil)

	// Encode the encrypted cookie value using base64.
	cookie.Value = base64.URLEncoding.EncodeToString(encryptedValue)

	return &cookie, nil
}

func (pt *phantomTokens) LoginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		if r.URL.Query().Get("state") == "" {
			state := uuid.NewString()
			oauth2Verifier := oauth2.GenerateVerifier()

			preLoginCookie := cookieValue{
				LoginState:     state,
				LoginValidator: oauth2Verifier,
			}
			cookie, _ := pt.newCookie(preLoginCookie)
			http.SetCookie(w, cookie)

			http.Redirect(w, r, pt.oauth2Config.AuthCodeURL(state, oauth2.S256ChallengeOption(oauth2Verifier)), http.StatusFound)
			return
		}

		cookie, err := pt.getCookie(w, r)
		if err != nil {
			pt.logger.Error("cookie failure", "err", err.Error())
			http.Error(w, "cookie failure: "+err.Error(), http.StatusBadRequest)
			return
		}

		if err != nil || r.URL.Query().Get("state") != cookie.LoginState {
			pt.logger.Error("state mismatch in login attempt")
			http.Error(w, "state did not match "+cookie.LoginState, http.StatusBadRequest)
			return
		}

		ctx := pt.providerClientContext(r.Context())

		oauth2Token, err := pt.oauth2Config.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(cookie.LoginValidator))
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
			return
		}

		oidcConfig := &oidc.Config{
			ClientID: pt.clientID,
		}
		verifier := pt.provider.Verifier(oidcConfig)

		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		resp := struct {
			OAuth2Token   *oauth2.Token
			IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
		}{oauth2Token, new(json.RawMessage)}

		if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data, err := json.MarshalIndent(resp, "", "    ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// TODO: Skapa riktigt random id i stället för uuid
		cookie.SessionID = uuid.NewString()
		cookie.Token = oauth2Token
		cookie.IdToken = rawIDToken

		cookie.SourceIP = r.Header.Get("X-Real-IP")

		newCookie, err := pt.newCookie(*cookie)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		pt.logger.Info("setting cookie", "value", newCookie.Value, "length", len(newCookie.Value))
		http.SetCookie(w, newCookie)

		pt.logger.Info("retrieved token via oidc", "contents", string(data))

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

		//storedTokens, ok := pt.tokens[cookie.SessionID]

		if cookie.Token.Valid() {
			//delete(pt.tokens, cookie.SessionID)

			logoutURL := pt.configURL + "/protocol/openid-connect/logout?id_token_hint=" + cookie.IdToken + "&post_logout_redirect_uri="
			logoutURL += url.QueryEscape("https://xn--lrudden-90a.local:8443/")

			http.Redirect(w, r, logoutURL, http.StatusFound)
			return
		}

		http.Redirect(w, r, "/", http.StatusFound)
	}
}
