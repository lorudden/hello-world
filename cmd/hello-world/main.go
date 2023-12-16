package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/lorudden/hello-world/components"
	qrcode "github.com/skip2/go-qrcode"
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

	r.Get("/api/swishqr/{size}/{phone}/{sum}/{msg}", NewSwishQRHandler())

	r.Get("/css/{hash}/tailwind.css", func() http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Content-Type", "text/css")
			w.Header().Add("Cache-Control", "public,max-age=31536000,immutable")
			w.WriteHeader(http.StatusOK)
			w.Write(css)
		}
	}())

	r.Get("/js/{hash}/htmx.min.js", func() http.HandlerFunc {
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

type simpleQRCode struct {
	Content string
	Size    int
}

func (code *simpleQRCode) generate() ([]byte, error) {
	qrCode, err := qrcode.Encode(code.Content, qrcode.Medium, code.Size)
	if err != nil {
		return nil, fmt.Errorf("could not generate a QR code: %v", err)
	}
	return qrCode, nil
}

func NewSwishQRHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		sizeStr, _ := url.QueryUnescape(chi.URLParam(r, "size"))
		phone, _ := url.QueryUnescape(chi.URLParam(r, "phone"))
		sumStr, _ := url.QueryUnescape(chi.URLParam(r, "sum"))
		msg, _ := url.QueryUnescape(chi.URLParam(r, "msg"))

		size, err := strconv.Atoi(sizeStr)
		if err != nil {
			reportError(w, http.StatusBadRequest, "size must be an integer")
			return
		}

		sum, err := strconv.Atoi(sumStr)
		if err != nil {
			reportError(w, http.StatusBadRequest, "sum must be an integer")
			return
		}

		content := fmt.Sprintf("C%s;%d;%s;0", phone, sum, msg)

		qrCode := simpleQRCode{Content: content, Size: size}
		codeData, err := qrCode.generate()
		if err != nil {
			reportError(w, http.StatusBadRequest, fmt.Sprintf("could not generate QR code. %v", err))
			return
		}

		w.Header().Set("Content-Type", "image/png")
		w.Header().Add("Cache-Control", "public,max-age=31536000,immutable")
		w.Write(codeData)
	}
}

func reportError(w http.ResponseWriter, header int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(header)
	json.NewEncoder(w).Encode(msg)
}
