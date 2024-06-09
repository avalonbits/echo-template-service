package web

import (
	"bytes"
	"fmt"
	"net/http"
	"net/mail"
	"regexp"
	"strings"

	"github.com/alexedwards/scs/v2"
	"github.com/avalonbits/echo-template-service/embeded"
	"github.com/avalonbits/echo-template-service/endpoints"
	"github.com/avalonbits/echo-template-service/service/recaptcha"
	"github.com/avalonbits/echo-template-service/service/user"
	"github.com/labstack/echo/v4"
	"github.com/microcosm-cc/bluemonday"
)

type SessionData struct {
	Email       string
	Name        string
	Handle      string
	InternalUID string
	ErrMsg      string
	CSRFToken   string
	Recaptcha   bool
}

func (sd SessionData) SignedIn() bool {
	return sd.InternalUID != ""
}

type Handler struct {
	domain    endpoints.Domain
	sess      *scs.SessionManager
	input     *bluemonday.Policy
	users     *user.Service
	recaptcha *recaptcha.Service
}

func New(
	domain endpoints.Domain,
	sess *scs.SessionManager,
	users *user.Service,
	recaptcha *recaptcha.Service,
) *Handler {
	return &Handler{
		domain:    domain,
		input:     bluemonday.StrictPolicy(),
		sess:      sess,
		users:     users,
		recaptcha: recaptcha,
	}
}

type signinRequest struct {
	Username string `form:"username"`
	Password string `form:"password"`
}

func (r *signinRequest) validate(c echo.Context, input *bluemonday.Policy) error {
	r.Username = input.Sanitize(strings.TrimSpace(r.Username))
	if !usernameRE.MatchString(r.Username) {
		return fmt.Errorf("invalid username")
	}

	r.Password = strings.TrimSpace(r.Password)
	if r.Password == "" {
		return fmt.Errorf("miising password")
	}
	if len(r.Password) < 10 {
		return fmt.Errorf("invalid password")
	}
	return nil
}

func (h *Handler) Signin(c echo.Context) error {
	r := signinRequest{}
	if err := h.validateRequest(c, &r, "signin_form"); err != nil {
		return err
	}

	ctx := c.Request().Context()
	p, err := h.users.Signin(ctx, r.Username, r.Password)
	if err != nil {
		return h.errTmpl(http.StatusInternalServerError, "signin_form", err.Error())
	}

	h.sess.Put(ctx, "uid", p.ID)
	return c.Redirect(http.StatusSeeOther, "/")
}

var usernameRE = regexp.MustCompile("^[a-z][a-z0-9_]*$")

type signupRequest struct {
	Username  string `form:"username"`
	Password  string `form:"password"`
	Confirm   string `form:"confirm"`
	Recaptcha string `form:"g-recaptcha-response"`
}

func (r *signupRequest) validate(c echo.Context, input *bluemonday.Policy) error {
	r.Username = input.Sanitize(strings.TrimSpace(r.Username))
	if !usernameRE.MatchString(r.Username) {
		return fmt.Errorf("invalid username")
	}

	r.Password = strings.TrimSpace(r.Password)
	r.Confirm = strings.TrimSpace(r.Confirm)
	if r.Password != r.Confirm || r.Password == "" {
		return fmt.Errorf("mismatched password/confirm")
	}
	if len(r.Password) < 10 {
		return fmt.Errorf("password too short")
	}
	return nil
}

func (h *Handler) Signup(c echo.Context) error {
	r := signupRequest{}
	if err := h.validateRequest(c, &r, "signup_form"); err != nil {
		return err
	}

	ctx := c.Request().Context()
	if err := h.recaptcha.Verify(ctx, r.Recaptcha); err != nil {
		return h.errTmpl(http.StatusBadRequest, "signup_form", "Invalid reCaptcha.")
	}

	uid, err := h.users.Signup(ctx, r.Username, r.Password)
	if err != nil {
		return h.errTmpl(http.StatusInternalServerError, "signup_form", err.Error())
	}

	h.sess.Put(ctx, "uid", uid)
	return c.Redirect(http.StatusSeeOther, "")
}

func (h *Handler) Signout(c echo.Context) error {
	if err := h.sess.Destroy(c.Request().Context()); err != nil {
		destroyCSRFCookie(c)
		return h.errMsg(http.StatusInternalServerError, err.Error())
	}
	return c.Redirect(http.StatusFound, "/")
}

type verifyEmailRequest struct {
	Email     string `form:"email"`
	Recaptcha string `form:"g-recaptcha-response"`
}

func (r *verifyEmailRequest) validate(c echo.Context, input *bluemonday.Policy) error {
	r.Email = input.Sanitize(strings.TrimSpace(r.Email))
	if r.Email == "" {
		return fmt.Errorf("missing email")
	}
	addr, err := mail.ParseAddress(r.Email)
	if err != nil {
		return fmt.Errorf("invalid email")
	}
	r.Email = addr.Address

	return nil
}

func (h *Handler) SendVerifyEmail(c echo.Context) error {
	r := verifyEmailRequest{}
	if err := h.validateRequest(c, &r); err != nil {
		return err
	}
	/*
		ctx := c.Request().Context()
		if err := h.recaptcha.Verify(ctx, r.Recaptcha); err != nil {
			return h.errTmpl(http.StatusBadRequest, "email_form", "Invalid reCaptcha.")
		}

		sess := getSessionData(c)
		_, err := h.emails.GenerateToken(
			ctx, sess.Handle, r.Email, sess.InternalUID, h.domain.Domain(),
		)
		if err != nil {
			return h.errTmpl(http.StatusInternalServerError, "email_form", err.Error())
		}
	*/
	return c.Redirect(http.StatusSeeOther, "")
}

func (h *Handler) VerifyEmail(c echo.Context) error {
	tk := c.QueryParam("tk")
	if tk == "" {
		return h.errTmpl(http.StatusBadRequest, "profile", "invalid email verification")
	}

	/*
		sess := getSessionData(c)
			ctx := c.Request().Context()
			if err := h.users.ValidateToken(ctx, sess.InternalUID, tk); err != nil {
				return h.errTmpl(http.StatusInternalServerError, "profile", err.Error())
			}

			plan, err := h.bills.GetVerifiedPlan(ctx)
			if err != nil {
				return h.errTmpl(http.StatusInternalServerError, "profile", err.Error())
			}
			if err := h.bills.Purchase(ctx, sess.InternalUID, plan); err != nil {
				return h.errTmpl(http.StatusInternalServerError, "profile", err.Error())
			}
	*/
	return c.Redirect(http.StatusSeeOther, "")
}

type webError struct {
	msg  string
	tmpl string
}

func (we webError) Error() string {
	return we.msg
}

func PageRenderer(page string) echo.HandlerFunc {
	return func(c echo.Context) error {
		sess := getSessionData(c)
		return c.Render(http.StatusOK, page, sess)
	}
}

func ErrorHandler(template *embeded.Template) func(error, echo.Context) {
	return func(err error, c echo.Context) {
		if c.Response().Committed {
			return
		}

		code := http.StatusInternalServerError
		msg := err.Error()
		tmpl := "index"
		he, ok := err.(*echo.HTTPError)
		if ok {
			code = he.Code
			out, ok := he.Internal.(webError)
			if ok {
				msg = out.msg
				if out.tmpl != "" {
					tmpl = out.tmpl
				}
			} else if m, _ := he.Message.(string); m != "" {
				msg = m
			}
		}

		if strings.HasPrefix(c.Request().URL.Path, "/static") {
			err = c.String(code, msg)
			return
		}

		sess := getSessionData(c)
		sess.ErrMsg = msg

		buf := bytes.Buffer{}
		template.Render(&buf, tmpl, sess, c)
		m := buf.String()
		err = c.HTML(code, m)
	}
}

func (h *Handler) errMsg(code int, msg string) error {
	return h.errTmpl(code, "index", msg)
}

func (h *Handler) errTmpl(code int, tmpl, msg string) error {
	return echo.NewHTTPError(code).WithInternal(webError{msg: msg, tmpl: tmpl})
}

type validator interface {
	validate(echo.Context, *bluemonday.Policy) error
}

func (h *Handler) validateRequest(c echo.Context, req validator, tmpl ...string) error {
	var err error
	if err = c.Bind(req); err == nil {
		err = req.validate(c, h.input)
	}

	errTmpl := "index"
	if err != nil {
		if len(tmpl) > 0 {
			errTmpl = tmpl[0]
		}
		return h.errTmpl(http.StatusBadRequest, errTmpl, err.Error())
	}
	return nil
}

func sanitize(in *bluemonday.Policy, str string) string {
	return strings.TrimSpace(in.Sanitize(str))
}

func getUser(c echo.Context) string {
	common := getSessionData(c)
	return common.InternalUID
}
func getSessionData(c echo.Context) SessionData {
	common, _ := c.Get("sessionData").(SessionData)
	return common
}

func destroyCSRFCookie(c echo.Context) {
	k, err := c.Cookie("_csc")
	if err != nil {
		return // nothing to do
	}
	k.Value = ""
	k.MaxAge = -1
	c.SetCookie(k)
}
