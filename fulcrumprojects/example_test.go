package fulcrumprojects_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"

	"github.com/growth-labs/packages-go/fulcrumprojects"
)

// Example reads the recorded /api/v2 snapshot fixture through the client the
// way golemd does before it builds a mutation: the device token stays in the
// client, the snapshot carries the workspace epoch every later call must echo.
func Example() {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v2/snapshot") {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, "testdata/snapshot.json")
	}))
	defer server.Close()
	client, err := fulcrumprojects.New(fulcrumprojects.Config{
		BaseURL:  server.URL,
		Token:    strings.Repeat("x", 32), // a real token comes from a mode-0600 file, never a flag
		ClientID: "example",
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	snapshot, err := client.Snapshot(context.Background(), "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	fmt.Println("epoch", snapshot.Epoch, "cursor", snapshot.Cursor)
	// Output: epoch 7 cursor 1234
}
