package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/lorudden/hello-world/components"
)

func main() {
	http.ListenAndServe(":3000", router())
}

func router() *chi.Mux {
	r := chi.NewRouter()
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		component := components.StartSida("Nu kör vi!", "Världen")
		component.Render(r.Context(), w)
	})
	return r
}
