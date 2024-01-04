package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/lorudden/hello-world/components"
	qrcode "github.com/skip2/go-qrcode"
)

func main() {

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	r := chi.NewRouter()

	css, sha256CSS := loadStaticAssetOrDie("./css/output.css")
	htmx, sha256HTMX := loadStaticAssetOrDie("./js/htmx.min.js")

	tokenExchange := NewPhantomTokenExchange(logger)

	r.Use(middleware.Logger)
	r.Use(tokenExchange.Middleware())

	r.Get("/", func() http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {

			authHeader := r.Header.Get("Authorization")
			if authHeader != "" {
				logger.Info("got auth header", "jwt", authHeader)
			}

			fmt.Printf("request from %s with accept %v\n", r.UserAgent(), r.Header["Accept"])

			w.Header().Add("Content-Type", "text/html")
			w.Header().Add("Cache-Control", "no-cache")
			w.WriteHeader(http.StatusOK)

			component := components.StartSida(sha256CSS, sha256HTMX, "Nu kör vi!", "Lörudden")
			component.Render(r.Context(), w)
		}
	}())

	r.Get("/login", tokenExchange.LoginHandler())
	r.Get("/logout", tokenExchange.LogoutHandler())

	r.Get("/health/ready", func() http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			resp, err := http.Get("http://keycloak:8080/health/ready")
			if err != nil || resp.StatusCode != http.StatusOK {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}

			w.WriteHeader(http.StatusOK)
		}
	}())

	r.Get("/api/swishqr/{size}/{phone}/{sum}/{msg}", NewSwishQRHandler())

	r.Get("/css/{hash}/tailwind.css", func() http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Content-Type", "text/css")
			w.Header().Add("Content-Encoding", "gzip")
			w.Header().Add("Cache-Control", "public,max-age=31536000,immutable")
			w.WriteHeader(http.StatusOK)
			w.Write(css)
		}
	}())

	r.Get("/js/{hash}/htmx.min.js", func() http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Content-Type", "text/css")
			w.Header().Add("Content-Encoding", "gzip")
			w.Header().Add("Cache-Control", "public,max-age=31536000,immutable")
			w.WriteHeader(http.StatusOK)
			w.Write(htmx)
		}
	}())

	r.Get("/menu/navbar", func() http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			navbar := components.NavBar()
			w.WriteHeader(http.StatusOK)

			navbar.Render(r.Context(), w)
		}
	}())

	r.Get("/menu/{menu}/", func() http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			menu, _ := url.QueryUnescape(chi.URLParam(r, "menu"))
			m := components.MenuContents(menu)
			w.WriteHeader(http.StatusOK)

			m.Render(r.Context(), w)
		}
	}())

	r.Get("/menu/{category}/{menu}", func() http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			menu, _ := url.QueryUnescape(chi.URLParam(r, "menu"))
			m := components.MenuContents(menu)
			w.WriteHeader(http.StatusOK)

			m.Render(r.Context(), w)
		}
	}())

	pages := map[string][]string{
		"home":           {"Här hittar du information om Lörudden och Lörans hamnförening", "Det lilla fiskeläget vid Bottenhavet söder om Sundsvall heter Lörudden, men kallas i dagligt tal för Löran. Därför används båda namnen när det på den här hemsidan informeras om platsen och om den verksamhet som bedrivs i den intresseförening som företräder såväl bofasta som fritidsboende i ett antal gemensamma angelägenheter.", "Du som bara är tillfällig gäst ute vid Brämösundet kan genom att klicka dig vidare till sidan Lörudden lära dig lite mer om vad det är för plats du besöker. Du hittar en del både om hur det var förr och om Lörudden av idag."},
		"hamnforeningen": {"Om Hamnföreningen", "Lörans Hamnförening har i sin nuvarande form funnits sedan någon gång på 1960-talet då det gamla hamnlaget på grund av en tilltagande flykt från yrkesfisket hade spelat ut sin roll. Det blev då uppenbart att gemensamma intressen i hamnen inte längre handlade enbart om fisket och förutsättningarna för att bedriva den näringen. Majoriteten av de boende – fast eller på fritiden – utgjordes redan vid den tiden av sommarstugeägare.", "Föreningen är ideell och den har idag ett 140-tal medlemmar. Medlemsmöten hålls företrädesvis sommartid då även flertalet av de fritidsboende finns på plats. Övrig tid på året hanterar den valda styrelsen löpande ärenden, håller medlemmarna informerade och skickar vid behov ut frågor till dem på remiss. Tanken är att merparten av informationen till och kontakterna med medlemmarna ska kunna kanaliseras via föreningens hemsida."},
		"lorudden":       {"Levande fiskeläge och ett paradis för besökare och sommarstugeägare", "För att komma till Lörudden, eller Löran som ortsbefolkningen säger, svänger man av från E4 vid Njurundabommen söder om Sundsvall och kör så långt vägen räcker, nästan ända fram till Bottenhavets strand vid Brämösundet.", "Här ligger ett litet fiskeläge med mycket gamla anor där det än idag bedrivs ett yrkesmässigt kustnära fiske. Här finns en välrenommerad fiskrestaurang, fiskaffär med rökeri, presentbutik, konstgalleri och ett mindre fiskemuseum.", "Sommartid är det alltid liv och rörelse bland de små röda stugorna med vita knutar som står uppradade i hamnen. Lörudden är ett mycket populärt utflyktsmål och för den som inte kommer för att göra ett restaurangbesök eller för att handla i butikerna är det kanske picknic med sol och bad ute på klipphällarna som hägrar."},
	}

	r.Get("/pages/{page}", func() http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			page, _ := url.QueryUnescape(chi.URLParam(r, "page"))
			contents := pages[page]

			p := components.Page(contents)
			w.WriteHeader(http.StatusOK)

			p.Render(r.Context(), w)
		}
	}())

	news := []components.NewsItem{
		{
			Title:  "Fiskemuséet stänger för säsongen",
			Body:   []string{"Vi tackar besökarna för den här säsongen och hälsar alla välkommen när vi öppnar nästa sommar."},
			Posted: time.Now(),
			Author: "Roland",
		},
		{
			Title:  "Arbetsdagen 2023-07-18",
			Body:   []string{"Ett stort tack till de 35 medlemmarna som ställde upp och gjorde en stor insats på arbetsdagen!", "Det blev mycket gjort och alla arbetade med stor flit, från stor till liten, alla hjälptes åt."},
			Posted: time.Now(),
			Author: "Roland",
		},
	}

	r.Get("/news/", func() http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			p := components.News(news)
			w.WriteHeader(http.StatusOK)

			p.Render(r.Context(), w)
		}
	}())

	http.ListenAndServe(":3000", r)
}

func isFromApp(r *http.Request) bool {
	for _, h := range r.Header["Accept"] {
		acceptedTypes := strings.Split(h, ",")
		fmt.Printf("accepted types %v\n", acceptedTypes)

		for _, t := range acceptedTypes {
			if t == "application/expo+json" {
				return true
			}
		}
	}

	return false
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

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)

	_, err = zw.Write(body)
	if err != nil {
		return nil, "", err
	}

	if err := zw.Close(); err != nil {
		return nil, "", err
	}

	return buf.Bytes(), sha256, nil
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
