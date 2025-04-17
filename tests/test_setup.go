package tests

import (
	"PartAuthService/handler"
	"PartAuthService/tests/mocks"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi"
)

type TestSetup struct {
	MockJwt  *mocks.MockJwtCreator
	MockRepo *mocks.MockRepoService
	MockSmtp *mocks.MockSmtpProvider
	Handler  *handler.Handler
	UserId   string
	Ip       string
	Req      *http.Request
	Rr       *httptest.ResponseRecorder
	Router   *chi.Mux
}

func NewTestSetup(t *testing.T) *TestSetup {
	mockJwt := new(mocks.MockJwtCreator)
	mockRepo := new(mocks.MockRepoService)
	mockSmtp := new(mocks.MockSmtpProvider)

	h := handler.NewHandler(mockJwt, mockRepo, mockSmtp)

	userId := "123"
	ip := "127.0.0.1"

	req, _ := http.NewRequest("GET", "/tokens/get/"+userId, nil)
	req.RemoteAddr = ip

	rr := httptest.NewRecorder()

	router := chi.NewRouter()
	handler.RegisterRoutes(h)
	router.Route("/tokens", func(r chi.Router) {
		r.Get("/get/{userId}", h.GetTokens)
		r.Post("/renew", h.RenewAccessToken)
	})

	return &TestSetup{
		MockJwt:  mockJwt,
		MockRepo: mockRepo,
		MockSmtp: mockSmtp,
		Handler:  h,
		UserId:   userId,
		Ip:       ip,
		Req:      req,
		Rr:       rr,
		Router:   router,
	}
}
