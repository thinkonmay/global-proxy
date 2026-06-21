package idempotency

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Drives the real register_message / mark_* SQL (init.sql) on a throwaway
// Postgres via psql Exec. Skipped without Docker.

func startPostgres(t *testing.T) testcontainers.Container {
	t.Helper()
	ctx := context.Background()
	initPath, err := filepath.Abs("testdata/postgres_init.sql")
	if err != nil {
		t.Fatalf("resolve init.sql: %v", err)
	}
	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: "postgres:16-alpine",
			Env: map[string]string{
				"POSTGRES_PASSWORD":         "postgres",
				"POSTGRES_HOST_AUTH_METHOD": "trust",
			},
			Files: []testcontainers.ContainerFile{{
				HostFilePath:      initPath,
				ContainerFilePath: "/docker-entrypoint-initdb.d/init.sql",
				FileMode:          0o644,
			}},
			ExposedPorts: []string{"5432/tcp"},
			WaitingFor: wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Skipf("postgres container unavailable: %v", err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(ctx) })
	return ctr
}

func psql(t *testing.T, ctr testcontainers.Container, sql string) string {
	t.Helper()
	code, r, err := ctr.Exec(context.Background(),
		[]string{"psql", "-U", "postgres", "-d", "postgres", "-tAc", sql}, tcexec.Multiplexed())
	if err != nil {
		t.Fatalf("psql exec: %v", err)
	}
	out, _ := io.ReadAll(r)
	if code != 0 {
		t.Fatalf("psql exit %d: %s", code, out)
	}
	return strings.TrimSpace(string(out))
}

func register(id string) string { return fmt.Sprintf("select register_message('%s')", id) }

// Fresh id acquires; any later register skips.
func TestRegisterMessage_AcquireThenSkip(t *testing.T) {
	ctr := startPostgres(t)
	if got := psql(t, ctr, register("a")); got != "acquired" {
		t.Fatalf("first register = %q, want acquired", got)
	}
	if got := psql(t, ctr, register("a")); got != "skip" {
		t.Fatalf("second register = %q, want skip", got)
	}
}

// A done id stays skipped.
func TestRegisterMessage_DoneSkips(t *testing.T) {
	ctr := startPostgres(t)
	psql(t, ctr, register("b"))
	psql(t, ctr, "select mark_done('b')")
	if got := psql(t, ctr, register("b")); got != "skip" {
		t.Fatalf("register after done = %q, want skip", got)
	}
}

// An errored id may be re-acquired for retry.
func TestRegisterMessage_ErrorAllowsRetry(t *testing.T) {
	ctr := startPostgres(t)
	psql(t, ctr, register("c"))
	psql(t, ctr, "select mark_error('c')")
	if got := psql(t, ctr, register("c")); got != "acquired" {
		t.Fatalf("register after error = %q, want acquired", got)
	}
}
