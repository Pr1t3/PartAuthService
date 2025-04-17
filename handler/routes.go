package handler

import (
	"net/http"

	"github.com/go-chi/chi"
)

var r *chi.Mux

func RegisterRoutes(handler *Handler) {
	r = chi.NewRouter()
	r.Route("/tokens", func(r chi.Router) {
		r.Get("/get/{userId}", handler.GetTokens)

		r.Post("/renew", handler.RenewAccessToken)
	})
}

func Start(addr string) {
	if err := http.ListenAndServe(addr, r); err != nil {
		panic(err)
	}
}
