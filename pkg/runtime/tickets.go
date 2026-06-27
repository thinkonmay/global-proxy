package runtime

import (
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/thinkonmay/thinkshare-daemon/persistent"
)

const ticketTTL = 5 * time.Second

// NewTicket holds a pending VM boot stream.
type NewTicket struct {
	ClusterID int64
	Session   *persistent.WorkerSession
	VolumeIDs []string
	Expires   time.Time
}

// AllocTicket holds a pending volume clone/reallocate stream.
type AllocTicket struct {
	ClusterID int64
	Request   *persistent.AllocateRequest
	Expires   time.Time
}

// TemplateTicket holds a pending superuser template rename+clone stream.
type TemplateTicket struct {
	ClusterID int64
	Rename    *persistent.RenameRequest
	Allocate  *persistent.AllocateRequest
	Expires   time.Time
}

// Tickets stores short-lived SSE stream tickets (mirrors PocketBase pending maps).
type Tickets struct {
	mu       sync.Mutex
	new      map[string]*NewTicket
	alloc    map[string]*AllocTicket
	template map[string]*TemplateTicket
	done     map[string]time.Time
}

// NewTickets creates an empty ticket store.
func NewTickets() *Tickets {
	return &Tickets{
		new:      map[string]*NewTicket{},
		alloc:    map[string]*AllocTicket{},
		template: map[string]*TemplateTicket{},
		done:     map[string]time.Time{},
	}
}

// IssueNew stores a new-session ticket and returns its id.
func (t *Tickets) IssueNew(clusterID int64, session *persistent.WorkerSession, volumeIDs []string) string {
	id := uuid.NewString()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.gcLocked()
	t.new[id] = &NewTicket{
		ClusterID: clusterID,
		Session:   session,
		VolumeIDs: append([]string(nil), volumeIDs...),
		Expires:   time.Now().Add(ticketTTL),
	}
	return id
}

// IsFinishedNew reports whether the stream already completed (PB newfinish → 204).
func (t *Tickets) IsFinishedNew(id string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.done[id]
	return ok
}

// TakeNew consumes a new-session ticket.
func (t *Tickets) TakeNew(id string) (*NewTicket, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.done[id]; ok {
		return nil, false
	}
	ticket, ok := t.new[id]
	if !ok {
		return nil, false
	}
	delete(t.new, id)
	return ticket, true
}

// FinishNew marks a new stream as completed (204 on replay).
func (t *Tickets) FinishNew(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.done[id] = time.Now().Add(ticketTTL)
}

// IssueAlloc stores an allocate/reallocate ticket.
func (t *Tickets) IssueAlloc(clusterID int64, req *persistent.AllocateRequest) string {
	id := uuid.NewString()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.gcLocked()
	t.alloc[id] = &AllocTicket{
		ClusterID: clusterID,
		Request:   req,
		Expires:   time.Now().Add(ticketTTL),
	}
	return id
}

// TakeAlloc consumes an allocate ticket.
func (t *Tickets) TakeAlloc(id string) (*AllocTicket, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.done[id]; ok {
		return nil, false
	}
	ticket, ok := t.alloc[id]
	if !ok {
		return nil, false
	}
	delete(t.alloc, id)
	return ticket, true
}

// FinishAlloc marks an allocate stream as completed.
func (t *Tickets) FinishAlloc(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.done[id] = time.Now().Add(ticketTTL)
}

// IssueTemplate stores a template-set ticket and returns its id.
func (t *Tickets) IssueTemplate(clusterID int64, rename *persistent.RenameRequest, allocate *persistent.AllocateRequest) string {
	id := uuid.NewString()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.gcLocked()
	t.template[id] = &TemplateTicket{
		ClusterID: clusterID,
		Rename:    rename,
		Allocate:  allocate,
		Expires:   time.Now().Add(ticketTTL),
	}
	return id
}

// TakeTemplate consumes a template ticket.
func (t *Tickets) TakeTemplate(id string) (*TemplateTicket, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.done[id]; ok {
		return nil, false
	}
	ticket, ok := t.template[id]
	if !ok {
		return nil, false
	}
	delete(t.template, id)
	return ticket, true
}

// FinishTemplate marks a template stream as completed.
func (t *Tickets) FinishTemplate(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.done[id] = time.Now().Add(ticketTTL)
}

func (t *Tickets) gcLocked() {
	now := time.Now()
	for id, ticket := range t.new {
		if now.After(ticket.Expires) {
			delete(t.new, id)
		}
	}
	for id, ticket := range t.alloc {
		if now.After(ticket.Expires) {
			delete(t.alloc, id)
		}
	}
	for id, ticket := range t.template {
		if now.After(ticket.Expires) {
			delete(t.template, id)
		}
	}
	for id, exp := range t.done {
		if now.After(exp) {
			delete(t.done, id)
		}
	}
}
