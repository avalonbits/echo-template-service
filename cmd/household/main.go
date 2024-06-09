package main

import (
	"context"

	"github.com/avalonbits/{{project}}/cmd/setup"
	"github.com/avalonbits/{{project}}/config"
)

func main() {
	server := setup.Echo(config.Get(context.Background()))
	defer server.Close()
	server.Logger.Fatal(server.Start(":1323"))
}
