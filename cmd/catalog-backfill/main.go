// Command catalog-backfill enqueues or runs Steam catalog enrichment for a JSON
// list of Steam app ids ({ "id": <app_id> }, ...). Writes slim rows to Postgres
// and full metadata to Elasticsearch via catalog.EnsureSteamStore.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/pkg/catalog"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/storeindex"
)

type steamIDEntry struct {
	ID int64 `json:"id"`
}

func main() {
	file := flag.String("file", "", "JSON array of {\"id\": steam_app_id}")
	concurrency := flag.Int("concurrency", 4, "parallel enrichment workers")
	delay := flag.Duration("delay", 0, "minimum delay between starting each job (rate limit Steam API)")
	limit := flag.Int("limit", 0, "process at most N ids (0 = all)")
	dryRun := flag.Bool("dry-run", false, "parse file and print count only")
	flag.Parse()

	if *file == "" {
		log.Fatal("-file required")
	}

	raw, err := os.ReadFile(*file)
	if err != nil {
		log.Fatalf("read file: %v", err)
	}
	var entries []steamIDEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		log.Fatalf("parse json: %v", err)
	}
	if *limit > 0 && *limit < len(entries) {
		entries = entries[:*limit]
	}

	seen := make(map[int64]struct{}, len(entries))
	ids := make([]int64, 0, len(entries))
	for _, e := range entries {
		if e.ID <= 0 {
			continue
		}
		if _, ok := seen[e.ID]; ok {
			continue
		}
		seen[e.ID] = struct{}{}
		ids = append(ids, e.ID)
	}

	log.Printf("loaded %d unique steam app ids from %s", len(ids), *file)
	if *dryRun {
		return
	}

	cfg, err := config.NewConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	pr := postgrest.New(postgrest.Config{
		URL:        cfg.PostgREST.URL,
		AnonKey:    cfg.PostgREST.AnonKey,
		ServiceKey: cfg.PostgREST.ServiceKey,
	})
	index := storeindex.NewClient(cfg.Logs.ElasticsearchURL, "")
	steamHTTP := &http.Client{Timeout: 60 * time.Second}

	workers := *concurrency
	if workers < 1 {
		workers = 1
	}
	if workers > 16 {
		workers = 16
	}

	ctx := context.Background()
	jobs := make(chan int64)
	var okCount, errCount atomic.Int64

	var wg sync.WaitGroup
	var delayMu sync.Mutex
	var lastStart time.Time
	throttle := func() {
		if *delay <= 0 {
			return
		}
		delayMu.Lock()
		defer delayMu.Unlock()
		if wait := *delay - time.Since(lastStart); wait > 0 {
			time.Sleep(wait)
		}
		lastStart = time.Now()
	}
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for appID := range jobs {
				if err := catalog.EnsureSteamStore(ctx, pr, steamHTTP, index, appID); err != nil {
					errCount.Add(1)
					log.Printf("error app_id=%d: %v", appID, err)
					continue
				}
				okCount.Add(1)
				done := okCount.Load() + errCount.Load()
				if done%100 == 0 || done == int64(len(ids)) {
					log.Printf("progress: done=%d ok=%d err=%d total=%d",
						done, okCount.Load(), errCount.Load(), len(ids))
				}
			}
		}()
	}

	start := time.Now()
	for _, id := range ids {
		throttle()
		jobs <- id
	}
	close(jobs)
	wg.Wait()

	log.Printf("finished in %s: ok=%d err=%d total=%d",
		time.Since(start).Round(time.Second), okCount.Load(), errCount.Load(), len(ids))

	if errCount.Load() > 0 {
		os.Exit(1)
	}
	fmt.Println("catalog backfill complete")
}
