package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/imirjar/api-service/internal/app/model"
	"github.com/imirjar/api-service/internal/app/store"
	"github.com/sirupsen/logrus"
)

const (
	sessionName        = "gopherschool"
	ctxKeyUser  ctxKey = iota
	ctxKeyRequestID
)

var (
	errIncorrectEmailOrPassword = errors.New("incorrect email or password")
	errNotAuthenticated         = errors.New("not authenticated")
)

type ctxKey int8

type server struct {
	router       *mux.Router
	logger       *logrus.Logger
	store        store.Store
	sessionStore sessions.Store
}

func newServer(store store.Store, sessionStore sessions.Store) *server {
	s := &server{
		router:       mux.NewRouter(),
		logger:       logrus.New(),
		store:        store,
		sessionStore: sessionStore,
	}

	s.configureRouter()

	return s
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *server) configureRouter() {
	s.router.Use(s.setRequestID)
	s.router.Use(s.logRequest)
	s.router.Use(handlers.CORS(handlers.AllowedOrigins([]string{"*", "http://0.0.0.0:3000", "http://0.0.0.0:8081"})))
	s.router.HandleFunc("/signup", s.handleUsersCreate()).Methods("POST")
	s.router.HandleFunc("/signin", s.handleSessionsCreate()).Methods("POST")

	//reports service
	// s.router.HandleFunc("/report/{id}", s.handleReport())
	s.router.HandleFunc("/reports/id", s.handleReport())
	s.router.HandleFunc("/reports", s.handleReports())

	private := s.router.PathPrefix("/private").Subrouter()
	private.Use(s.authenticateUser)
	private.HandleFunc("/whoami", s.handleWhoami())
}

func (s *server) setRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := uuid.New().String()
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyRequestID, id)))
	})
}

func (s *server) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := s.logger.WithFields(logrus.Fields{
			"remote_addr": r.RemoteAddr,
			"request_id":  r.Context().Value(ctxKeyRequestID),
		})
		logger.Infof("started %s %s", r.Method, r.RequestURI)

		start := time.Now()
		rw := &responseWriter{w, http.StatusOK}
		next.ServeHTTP(rw, r)

		var level logrus.Level
		switch {
		case rw.code >= 500:
			level = logrus.ErrorLevel
		case rw.code >= 400:
			level = logrus.WarnLevel
		default:
			level = logrus.InfoLevel
		}
		logger.Logf(
			level,
			"completed with %d %s in %v",
			rw.code,
			http.StatusText(rw.code),
			time.Now().Sub(start),
		)
	})
}

func (s *server) authenticateUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := s.sessionStore.Get(r, sessionName)
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		id, ok := session.Values["user_id"]
		if !ok {
			s.error(w, r, http.StatusUnauthorized, errNotAuthenticated)
			return
		}

		u, err := s.store.User().Find(id.(int))
		if err != nil {
			s.error(w, r, http.StatusUnauthorized, errNotAuthenticated)
			return
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyUser, u)))
	})
}

func (s *server) handleUsersCreate() http.HandlerFunc {
	type request struct {
		Email      string `json:"email"`
		Password   string `json:"password"`
		Username   string `json:"username"`
		Surname    string `json:"surname"`
		Patronymic string `json:"patronymic"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		u := &model.User{
			Email:      req.Email,
			Password:   req.Password,
			Username:   req.Username,
			Surname:    req.Surname,
			Patronymic: req.Patronymic,
		}

		if err := s.store.User().Create(u); err != nil {
			s.error(w, r, http.StatusUnprocessableEntity, err)
			return
		}

		u.Sanitize()
		s.respond(w, r, http.StatusCreated, u)
	}
}

func (s *server) handleReports() http.HandlerFunc {
	type Report struct {
		Name string `json:"name"`
	}

	type Category struct {
		Name    string   `json:"name"`
		Reports []Report `json:"reports"`
	}

	type Reports struct {
		Categories []Category `json:"categories"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		reports := &Reports{}

		req, err := http.NewRequest(http.MethodGet, "http://localhost:8081", nil)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err) //client: could not create request
			return
			// s.respond(w, r, http.StatusBadGateway, err)
			// return
		}

		res, err := http.DefaultClient.Do(req)

		if err := json.NewDecoder(res.Body).Decode(reports); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}
		s.respond(w, r, http.StatusOK, reports)
	}
}

func (s *server) handleReport() http.HandlerFunc {
	type Report struct {
		Name string `json:"name"`
		Data string `json:"data"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("#####1###")
		report := &Report{}

		// vars := mux.Vars(r)

		req, err := http.NewRequest(http.MethodGet, "http://localhost:8081/id", nil)
		if err != nil {
			s.error(w, r, http.StatusBadRequest, err) //client: could not create request
			return
			// s.respond(w, r, http.StatusBadGateway, err)
			// return
		}
		fmt.Println("#####2###")
		res, err := http.DefaultClient.Do(req)

		if err := json.NewDecoder(res.Body).Decode(report); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}
		fmt.Println("#####3###")
		s.respond(w, r, http.StatusOK, report)
	}
}

func (s *server) handleSessionsCreate() http.HandlerFunc {
	type request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.error(w, r, http.StatusBadRequest, err)
			return
		}

		u, err := s.store.User().FindByEmail(req.Email)
		if err != nil || !u.ComparePassword(req.Password) {
			s.error(w, r, http.StatusUnauthorized, errIncorrectEmailOrPassword)
			return
		}

		session, err := s.sessionStore.Get(r, sessionName)
		if err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		session.Values["user_id"] = u.ID
		if err := s.sessionStore.Save(r, w, session); err != nil {
			s.error(w, r, http.StatusInternalServerError, err)
			return
		}

		s.respond(w, r, http.StatusOK, nil)
	}
}

func (s *server) handleWhoami() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.respond(w, r, http.StatusOK, r.Context().Value(ctxKeyUser).(*model.User))
	}
}

func (s *server) error(w http.ResponseWriter, r *http.Request, code int, err error) {
	s.respond(w, r, code, map[string]string{"error": err.Error()})
}

func (s *server) respond(w http.ResponseWriter, r *http.Request, code int, data interface{}) {
	w.WriteHeader(code)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}
