package setup

import (
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/alexedwards/scs/sqlite3store"
	"github.com/alexedwards/scs/v2"
	"github.com/avalonbits/echo-template-service/config"
	"github.com/avalonbits/echo-template-service/embeded"
	"github.com/avalonbits/echo-template-service/endpoints"
	"github.com/avalonbits/echo-template-service/endpoints/web"
	"github.com/avalonbits/echo-template-service/service/recaptcha"
	"github.com/avalonbits/echo-template-service/service/user"
	"github.com/avalonbits/echo-template-service/storage"
	"github.com/avalonbits/echo-template-service/storage/datastore"
	"github.com/honeycombio/otel-config-go/otelconfig"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.opentelemetry.io/contrib/instrumentation/github.com/labstack/echo/otelecho"
	"go.opentelemetry.io/contrib/processors/baggage/baggagetrace"
	"go.opentelemetry.io/otel"

	session "github.com/spazzymoto/echo-scs-session"
)

func Echo(cfg config.Config) Server {
	server := Server{}

	e := echo.New()
	server.Echo = e

	templates := embeded.Templates()
	e.Renderer = templates
	e.HTTPErrorHandler = web.ErrorHandler(templates)

	// Setup honeycomb.io
	if cfg.ServiceName != "" {
		// Setup honeycomb instrumentation.
		bsp := baggagetrace.New()
		otelShutdown, err := otelconfig.ConfigureOpenTelemetry(
			otelconfig.WithSpanProcessor(bsp),
		)
		if err != nil {
			log.Fatalf("error setting up OTel SDK - %e", err)
		}
		server.otelShutdown = otelShutdown
		e.Use(otelecho.Middleware(cfg.ServiceName))
	}
	e.Use(middleware.BodyLimit("10k"))

	// Setup CSRF protection.
	e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{
		TokenLookup:    "form:csrf_token",
		CookieMaxAge:   int(1 * time.Hour / time.Second),
		CookieHTTPOnly: true,
		CookieSecure:   true,
		CookieName:     "_csc",
		ContextKey:     "csc",
		CookiePath:     "/",
		CookieSameSite: http.SameSiteStrictMode,
		Skipper: func(c echo.Context) bool {
			path := c.Request().URL.Path
			return strings.HasPrefix(path, "/static") || path == "/payment_hook"
		},
	}))

	// Setup CORS.
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{cfg.AppURL()},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept},
	}))

	// Setup main DB and session handling.
	db, err := storage.GetDB(
		cfg.Database,
		datastore.Migrations,
		datastore.Factory,
	)
	if err != nil {
		log.Fatalf("error setting up database: %v", err)
	}
	server.db = db

	sessionManager := scs.New()
	sessionManager.Store = sqlite3store.New(db.RDBMS())
	sessionManager.Lifetime = 24 * time.Hour * 7
	sessionManager.IdleTimeout = 24 * time.Hour
	sessionManager.Cookie.Name = "_s"
	sessionManager.Cookie.HttpOnly = true
	sessionManager.Cookie.Path = "/"
	sessionManager.Cookie.Persist = true
	sessionManager.Cookie.Secure = true
	sessionManager.Cookie.SameSite = http.SameSiteLaxMode
	e.Use(session.LoadAndSave(sessionManager))

	// Setup handlers
	tracer := otel.Tracer(cfg.ServiceName)
	recaptcha := recaptcha.New(tracer, cfg.RecaptchaToken)
	users := user.New(db)
	handlers := web.New(
		endpoints.Domain(cfg.FullDomain()),
		sessionManager,
		users,
		recaptcha,
	)
	e.Use(sessionDataMiddleware(sessionManager, users, cfg.RecaptchaToken != ""))

	// Setup endpoints.
	templates.NewView("index", "base.tmpl", "menu.tmpl")
	e.GET("/", web.PageRenderer("index"))

	templates.NewView("signin_form", "base.tmpl", "signin_form.tmpl", "menu.tmpl")
	e.GET("/form/signin", web.PageRenderer("signin_form"), signedOutMiddleware)
	e.POST("/form/signin", handlers.Signin, signedOutMiddleware)

	templates.NewView("signup_form", "base.tmpl", "signup_form.tmpl", "menu.tmpl")
	e.GET("/form/signup", web.PageRenderer("signup_form"), signedOutMiddleware)
	e.POST("/form/signup", handlers.Signup, signedOutMiddleware)
	e.GET("/signout", handlers.Signout, signedInMiddleware)

	// Setup static page serving.
	staticG := e.Group("static")
	staticG.Use(middleware.Gzip())
	staticG.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Set cache control header to 1 year so we can cache for a long time any static file.
			// This means if we need to update a static file, we need to change its name.
			//
			// WARNING: This will cache 4xx-5XX responses as well. We should instead write our own Static
			// handler that caches only on success.
			c.Response().Header().Set(
				"Cache-Control",
				"max-age="+strconv.Itoa(int(365*24*time.Hour/time.Second)),
			)
			return next(c)
		}
	})
	staticG.StaticFS("/", embeded.Static())

	return server
}

type Server struct {
	*echo.Echo

	db           *storage.DB[datastore.Queries]
	otelShutdown func()
}

func (s Server) Cleanup() {
	s.otelShutdown()
}

func sessionDataMiddleware(
	sessionManager *scs.SessionManager,
	users *user.Service,
	recaptchaOn bool,
) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			req := c.Request()
			// Skip static endpoints.
			if strings.HasPrefix(req.URL.Path, "/static") {
				return next(c)
			}

			sessionData := web.SessionData{
				Recaptcha: recaptchaOn,
			}
			ctx := req.Context()
			uid := sessionManager.GetString(ctx, "uid")
			if uid != "" {
				person, err := users.GetUser(ctx, uid)
				if err != nil {
					// Instead, need to clear the session/cookie and redirect to signin.
					panic(err)
				}
				sessionData.Email = person.Email
				sessionData.Name = person.Name
				sessionData.InternalUID = person.ID
				sessionData.Handle = person.Handle
			}
			tk, ok := c.Get("csc").(string)
			if ok {
				sessionData.CSRFToken = tk
			}

			c.Set("sessionData", sessionData)
			return next(c)
		}
	}
}

func signedInMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sess, _ := c.Get("sessionData").(web.SessionData)
		if !sess.SignedIn() {
			return c.Redirect(http.StatusSeeOther, "/form/signin")
		}
		return next(c)
	}
}

func signedOutMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sess, _ := c.Get("sessionData").(web.SessionData)
		if sess.SignedIn() {
			return c.Redirect(http.StatusSeeOther, "/")
		}
		return next(c)
	}
}
