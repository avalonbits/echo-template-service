package config

import (
	"context"
	"strconv"
	"strings"

	"github.com/sethvargo/go-envconfig"
)

func Get(ctx context.Context) Config {
	c := Config{}
	if err := envconfig.Process(ctx, &c); err != nil {
		panic(err)
	}
	validate(&c)
	return c
}

type Config struct {
	Domain         string `env:"DOMAIN_NAME"`
	Port           string `env:"PORT"`
	Database       string `env:"DATABASE"`
	ServiceName    string `env:"OTEL_SERVICE_NAME"`
	BindAddress    string `env:"BIND_ADDRESS"`
	RecaptchaToken string `env:"RECAPTCHA_TOKEN"`
}

func (c Config) AppURL() string {
	scheme := "https://"
	if strings.HasPrefix(c.Domain, "localhost") {
		scheme = "http://"
	}

	return strings.Join([]string{scheme, c.Domain, ":", c.Port}, "")
}
func (c Config) FullDomain() string {
	if strings.HasPrefix(c.Domain, "localhost") {
		return c.Domain + ":" + c.Port
	} else {
		return c.Domain
	}
}

func validate(cfg *Config) Config {
	if cfg.Database == "" {
		panic("required value for Database")
	}

	if cfg.Port == "" {
		cfg.Port = "9001"
	} else if _, err := strconv.ParseInt(cfg.Port, 10, 16); err != nil {
		panic("invalid port number: " + cfg.Port)
	}

	if cfg.BindAddress == "" {
		cfg.BindAddress = "localhost"
	}

	return *cfg
}
