package main

import (
	"context"

	"github.com/avalonbits/echo-template-service/cmd/setup"
	"github.com/avalonbits/echo-template-service/config"
)

func main() {
	server := setup.Echo(config.Get(context.Background()))
	defer server.Close()
	server.Logger.Fatal(server.Start(":1323"))
}
