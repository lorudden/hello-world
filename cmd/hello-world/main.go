package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/lorudden/hello-world/components"
)

func main() {

	r := chi.NewRouter()

	css, sha256CSS := loadStaticAssetOrDie("./css/output.css")
	htmx, sha256HTMX := loadStaticAssetOrDie("./js/htmx.min.js")

	r.Get("/", func() http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Content-Type", "text/html")
			w.Header().Add("Cache-Control", "no-cache")
			w.WriteHeader(http.StatusOK)

			component := components.StartSida(sha256CSS, sha256HTMX, "Nu kör vi!", "Världen")
			component.Render(r.Context(), w)
		}
	}())

	r.Get("/css/{version}/tailwind.css", func() http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Content-Type", "text/css")
			w.Header().Add("Cache-Control", "public,max-age=31536000,immutable")
			w.WriteHeader(http.StatusOK)
			w.Write(css)
		}
	}())

	r.Get("/js/{version}/htmx.min.js", func() http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Content-Type", "text/css")
			w.Header().Add("Cache-Control", "public,max-age=31536000,immutable")
			w.WriteHeader(http.StatusOK)
			w.Write(htmx)
		}
	}())

	http.ListenAndServe(":3000", r)
}

func loadStaticAssetOrDie(path string) ([]byte, string) {
	body, sha, err := loadStaticAsset(path)
	if err != nil {
		panic(err.Error())
	}
	return body, sha
}

func loadStaticAsset(path string) ([]byte, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}

	defer f.Close()

	body, err := io.ReadAll(f)
	if err != nil {
		return nil, "", err
	}

	sha256 := fmt.Sprintf("%x", sha256.Sum256(body))

	return body, sha256, nil
}
