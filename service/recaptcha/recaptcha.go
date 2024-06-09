package recaptcha

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/otel/trace"
)

type Service struct {
	client *http.Client
	token  string
	tracer trace.Tracer
}

func New(tracer trace.Tracer, token string) *Service {
	return &Service{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		token:  token,
		tracer: tracer,
	}
}

type verifyResponse struct {
	Success     bool     `json:"success"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	ErrorCodes  []string `json:"error-codes"`
}

func (s *Service) Verify(ctx context.Context, response string) error {
	if s.token == "" {
		// Recaptch wasn't setup.
		return nil
	}
	const url = "https://www.google.com/recaptcha/api/siteverify"
	const body = "secret=%s&response=%s"

	ctx, span := s.tracer.Start(ctx, "recaptch-verify")
	defer span.End()

	buf := []byte(fmt.Sprintf(body, s.token, response))
	reqBody := bytes.NewBuffer(buf)
	req, err := http.NewRequest(http.MethodPost, url, reqBody)
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := s.client.Do(req.WithContext(ctx))
	if err != nil {
		return err
	}
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	verify := verifyResponse{}
	if err := json.Unmarshal(data, &verify); err != nil {
		return err
	}

	if !verify.Success {
		return fmt.Errorf("invalid verification: %q", strings.Join(verify.ErrorCodes, ","))
	}

	return nil
}
