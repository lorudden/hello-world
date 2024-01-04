package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
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

type storedTokens struct {
	idToken   string
	authToken *oauth2.Token
}

type phantomTokens struct {
	logger *slog.Logger

	cookieName string

	tokens map[string]storedTokens
}

func NewPhantomTokenExchange(logger *slog.Logger) PhantomTokenExchange {
	return &phantomTokens{
		logger:     logger,
		cookieName: "hello-id",
		tokens:     map[string]storedTokens{},
	}
}

type sessionID string

const sessionIDKey sessionID = "session-id"

func (pt *phantomTokens) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(pt.cookieName)
			if err == nil {
				encryptedValue, err := base64.URLEncoding.DecodeString(cookie.Value)
				if err != nil {
					pt.clearCookie(w)
					next.ServeHTTP(w, r)
					return
				}

				secretKey, _ := hex.DecodeString("13d6b4dff8f84a10851021ec8608f814570d562c92fe6b5ec4c9f595bcb3234b")

				// Create a new AES cipher block from the secret key.
				block, err := aes.NewCipher(secretKey)
				if err != nil {
					pt.logger.Error("cipher failure", "err", err.Error())
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				// Wrap the cipher block in Galois Counter Mode.
				aesGCM, err := cipher.NewGCM(block)
				if err != nil {
					pt.logger.Error("cipher failure", "err", err.Error())
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				// Get the nonce size.
				nonceSize := aesGCM.NonceSize()

				// To avoid a potential 'index out of range' panic in the next step, we
				// check that the length of the encrypted value is at least the nonce
				// size.
				if len(encryptedValue) < nonceSize {
					pt.logger.Error("encrypted cookie value too short", "length", len(encryptedValue))
					pt.clearCookie(w)
					w.WriteHeader(http.StatusBadRequest)
					return
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
					return
				}

				// The plaintext value is in the format "{cookie name}:{cookie value}". We
				// use strings.Cut() to split it on the first ":" character.
				expectedName, cookieValue, ok := strings.Cut(string(plaintext), ":")
				if !ok {
					pt.logger.Error("malformed cookie value")
					pt.clearCookie(w)
					w.WriteHeader(http.StatusBadRequest)
					return
				}

				// Check that the cookie name is the expected one and hasn't been changed.
				if expectedName != pt.cookieName {
					pt.logger.Error("invalid cookie name")
					pt.clearCookie(w)
					w.WriteHeader(http.StatusBadRequest)
					return
				}

				// cookie was found
				pt.logger.Info("cookie found", "value", cookieValue)

				if tokens, ok := pt.tokens[cookieValue]; ok {
					r.Header.Add("Authorization", "Bearer "+tokens.authToken.AccessToken)

					ctx := context.WithValue(r.Context(), sessionIDKey, cookieValue)
					r = r.WithContext(ctx)
				} else {
					pt.clearCookie(w)
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
}

func (pt *phantomTokens) newCookie(value string) (*http.Cookie, error) {
	cookie := http.Cookie{
		Name:     pt.cookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	secretKey, _ := hex.DecodeString("13d6b4dff8f84a10851021ec8608f814570d562c92fe6b5ec4c9f595bcb3234b")

	// Create a new AES cipher block from the secret key.
	block, err := aes.NewCipher(secretKey)
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

	// Prepare the plaintext input for encryption. Because we want to
	// authenticate the cookie name as well as the value, we make this plaintext
	// in the format "{cookie name}:{cookie value}". We use the : character as a
	// separator because it is an invalid character for cookie names and
	// therefore shouldn't appear in them.
	plaintext := fmt.Sprintf("%s:%s", cookie.Name, cookie.Value)

	// Encrypt the data using aesGCM.Seal(). By passing the nonce as the first
	// parameter, the encrypted data will be appended to the nonce — meaning
	// that the returned encryptedValue variable will be in the format
	// "{nonce}{encrypted plaintext data}".
	encryptedValue := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)

	// Encode the encrypted cookie value using base64.
	cookie.Value = base64.URLEncoding.EncodeToString(encryptedValue)

	return &cookie, nil
}

func (pt *phantomTokens) LoginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		configURL := "https://iam.xn--lrudden-90a.local:8444/realms/lorudden-test"

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}
		ctx := context.WithValue(r.Context(), oauth2.HTTPClient, client)

		provider, err := oidc.NewProvider(ctx, configURL)
		for err != nil {
			pt.logger.Info("failed to connect to oidc provider", "err", err.Error())
			time.Sleep(1 * time.Second)
			provider, err = oidc.NewProvider(ctx, configURL)
		}

		clientID := "hello-world"
		clientSecret := "oPMxXzsk6lLntEJqsOpqGZZf4PXHGvRT"

		redirectURL := "https://xn--lrudden-90a.local:8443/login"
		// Configure an OpenID Connect aware OAuth2 client.
		oauth2Config := oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		}

		state := "268e6917-3ce0-4eda-a404-ed8858968b5c"

		oidcConfig := &oidc.Config{
			ClientID: clientID,
		}
		verifier := provider.Verifier(oidcConfig)

		if r.URL.Query().Get("state") == "" {
			http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
			return
		}

		if r.URL.Query().Get("state") != state {
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}

		oauth2Token, err := oauth2Config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
			return
		}
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

		tokenID := uuid.NewString()
		pt.tokens[tokenID] = storedTokens{
			authToken: oauth2Token,
			idToken:   rawIDToken,
		}

		cookie, err := pt.newCookie(tokenID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		http.SetCookie(w, cookie)

		pt.logger.Info("retrieved token via iodc", "contents", string(data))

		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func (pt *phantomTokens) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		untypedSessionID := r.Context().Value(sessionIDKey)
		if untypedSessionID == nil {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		pt.clearCookie(w)

		sessionID := untypedSessionID.(string)
		storedTokens, ok := pt.tokens[string(sessionID)]

		if ok {
			delete(pt.tokens, sessionID)

			logoutURL := "https://iam.xn--lrudden-90a.local:8444/realms/lorudden-test/protocol/openid-connect/logout?id_token_hint=" + storedTokens.idToken + "&post_logout_redirect_uri="
			logoutURL += url.QueryEscape("https://xn--lrudden-90a.local:8443/")

			http.Redirect(w, r, logoutURL, http.StatusFound)
			return
		}

		http.Redirect(w, r, "/", http.StatusFound)
	}
}
