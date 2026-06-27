package router_test

import (
	"net/http"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/router"
)

func TestJobsHistoryAndEventsRoutesDoNotConflict(t *testing.T) {
	mux := http.NewServeMux()
	v1 := router.V1(mux)
	v1.GETExact("/jobs/history", func(w http.ResponseWriter, r *http.Request) {})
	v1.GET("/jobs/{jobId}/events", func(w http.ResponseWriter, r *http.Request) {})
}
