package authz

import (
	"context"
	"net/http"
)

type loggedInKey string

const LoggedIn loggedInKey = "logged-in"

func NewContextFromAuthorizationHeader(ctx context.Context, r *http.Request) (context.Context, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		ctx = context.WithValue(ctx, LoggedIn, "yes")
	}
	return ctx, nil
}

func Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ctx, err := NewContextFromAuthorizationHeader(r.Context(), r)
			if err == nil {
				r = r.WithContext(ctx)
			}
			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}

func IsLoggedIn(ctx context.Context) bool {
	if value, ok := ctx.Value(LoggedIn).(string); ok {
		return value == "yes"
	}
	return false
}
