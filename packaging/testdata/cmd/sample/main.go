package main

import (
	"encoding/json"
	"os"

	"github.com/growth-labs/packages-go/packaging/provenance"
)

func main() {
	if err := json.NewEncoder(os.Stdout).Encode(provenance.Info()); err != nil {
		panic(err)
	}
}
