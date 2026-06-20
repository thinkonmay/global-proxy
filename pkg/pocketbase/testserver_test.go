package pocketbase

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	pbtests "github.com/pocketbase/pocketbase/tests"
)

const (
	testAdminEmail = "admin@test.com"
	testAdminPass  = "testpass123"
)

type pbTestEnv struct {
	app *pbtests.TestApp
	URL string
}

func startPocketBase(t *testing.T) *pbTestEnv {
	t.Helper()

	app, err := pbtests.NewTestApp()
	if err != nil {
		t.Fatalf("NewTestApp: %v", err)
	}
	t.Cleanup(app.Cleanup)

	if err := upsertSuperuser(app, testAdminEmail, testAdminPass); err != nil {
		t.Fatalf("upsertSuperuser: %v", err)
	}
	if err := disableUsersMFA(app); err != nil {
		t.Fatalf("disableUsersMFA: %v", err)
	}
	if err := ensureVolumesCollection(app); err != nil {
		t.Fatalf("ensureVolumesCollection: %v", err)
	}

	mux, err := newPocketBaseMux(app)
	if err != nil {
		t.Fatalf("newPocketBaseMux: %v", err)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &pbTestEnv{app: app, URL: srv.URL}
}

func newPocketBaseMux(app core.App) (http.Handler, error) {
	baseRouter, err := apis.NewRouter(app)
	if err != nil {
		return nil, err
	}

	serveEvent := new(core.ServeEvent)
	serveEvent.App = app
	serveEvent.Router = baseRouter

	var mux http.Handler
	err = app.OnServe().Trigger(serveEvent, func(e *core.ServeEvent) error {
		var buildErr error
		mux, buildErr = e.Router.BuildMux()
		if buildErr != nil {
			return buildErr
		}
		return e.Next()
	})
	if err != nil {
		return nil, err
	}
	return mux, nil
}

func upsertSuperuser(app core.App, email, password string) error {
	col, err := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
	if err != nil {
		return err
	}

	record, err := app.FindAuthRecordByEmail(col, email)
	if err != nil {
		record = core.NewRecord(col)
	}
	record.SetEmail(email)
	record.SetPassword(password)
	return app.Save(record)
}

func disableUsersMFA(app core.App) error {
	col, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		return err
	}
	col.MFA.Enabled = false
	return app.Save(col)
}

func ensureVolumesCollection(app core.App) error {
	_, err := app.FindCollectionByNameOrId("volumes")
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	col := core.NewBaseCollection("volumes")
	col.Fields.Add(&core.TextField{Name: "user"})
	col.Fields.Add(&core.TextField{Name: "local_id"})
	col.Fields.Add(&core.TextField{Name: "name"})
	col.Fields.Add(&core.TextField{Name: "tier"})
	col.Fields.Add(&core.JSONField{Name: "configuration"})
	return app.Save(col)
}

func testClient(baseURL string) *Client {
	return New(Config{
		URL:      baseURL,
		Username: testAdminEmail,
		Password: testAdminPass,
	})
}

func userAuthToken(t *testing.T, baseURL, email, password string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"identity": email,
		"password": password,
	})
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		baseURL+"/api/collections/users/auth-with-password",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("user auth request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("user auth: %v", err)
	}
	defer func() { _ = res.Body.Close() }()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read user auth body: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("user auth status %d: %s", res.StatusCode, data)
	}
	var out AuthResponse
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("decode user auth: %v", err)
	}
	if out.Token == "" {
		t.Fatal("empty user auth token")
	}
	return out.Token
}
