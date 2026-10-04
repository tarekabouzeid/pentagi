// Package sandbox names the sandbox runtimes a flow's tools can run in and tracks which runtime each flow is bound to.
//
// A runtime is anything satisfying docker.DockerClient, so terminal, file and flow-file code is runtime-agnostic.
package sandbox

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"

	"pentagi/pkg/database"
)

type Kind string

const (
	KindDocker    Kind = "docker"
	KindOpenShell Kind = "openshell"
)

func (k Kind) Valid() bool {
	switch k {
	case KindDocker, KindOpenShell:
		return true
	default:
		return false
	}
}

// Selection is persisted under "sandbox" in the flow's functions so the binding survives a restart. An empty Backend is Docker. Profile is runtime specific (for OpenShell, the policy preset).
type Selection struct {
	Backend Kind   `form:"backend,omitempty" json:"backend,omitempty" validate:"omitempty"`
	Profile string `form:"profile,omitempty" json:"profile,omitempty" validate:"omitempty"`
}

func (s Selection) Kind() Kind {
	if s.Backend == "" {
		return KindDocker
	}
	return s.Backend
}

func SelectionFromFunctions(raw []byte) (Selection, error) {
	if len(raw) == 0 {
		return Selection{}, nil
	}

	var functions struct {
		Sandbox *Selection `json:"sandbox"`
	}
	if err := json.Unmarshal(raw, &functions); err != nil {
		return Selection{}, fmt.Errorf("failed to read the sandbox of the flow functions: %w", err)
	}
	if functions.Sandbox == nil {
		return Selection{}, nil
	}

	return *functions.Sandbox, nil
}

var ErrUnavailable = errors.New("sandbox backend is not enabled")

type flowReader interface {
	GetFlow(ctx context.Context, id int64) (database.Flow, error)
}

// Registry is safe for concurrent use.
type Registry[B any] struct {
	db       flowReader
	def      Kind
	backends map[Kind]B

	mx    sync.RWMutex
	flows map[int64]Kind
}

func NewRegistry[B any](db flowReader, def Kind, backends map[Kind]B) (*Registry[B], error) {
	if def == "" {
		def = KindDocker
	}
	if !def.Valid() {
		return nil, fmt.Errorf("unknown default sandbox backend '%s'", def)
	}
	if _, ok := backends[def]; !ok {
		return nil, fmt.Errorf("default sandbox backend '%s': %w", def, ErrUnavailable)
	}

	return &Registry[B]{
		db:       db,
		def:      def,
		backends: backends,
		flows:    make(map[int64]Kind),
	}, nil
}

func (r *Registry[B]) Default() Kind {
	return r.def
}

func (r *Registry[B]) Kinds() []Kind {
	kinds := make([]Kind, 0, len(r.backends))
	for kind := range r.backends {
		if kind != r.def {
			kinds = append(kinds, kind)
		}
	}
	slices.Sort(kinds)

	return append([]Kind{r.def}, kinds...)
}

// Select always returns a named backend so what is persisted does not depend on the default at read time.
func (r *Registry[B]) Select(requested *Selection) (Selection, error) {
	var sel Selection
	if requested != nil {
		sel = *requested
	}
	if sel.Backend == "" {
		sel.Backend = r.def
	}
	if !sel.Backend.Valid() {
		return Selection{}, fmt.Errorf("unknown sandbox backend '%s'", sel.Backend)
	}
	if _, ok := r.backends[sel.Backend]; !ok {
		return Selection{}, fmt.Errorf("sandbox backend '%s': %w", sel.Backend, ErrUnavailable)
	}

	return sel, nil
}

func (r *Registry[B]) Backend(kind Kind) (B, error) {
	backend, ok := r.backends[kind]
	if !ok {
		var zero B
		return zero, fmt.Errorf("sandbox backend '%s': %w", kind, ErrUnavailable)
	}

	return backend, nil
}

func (r *Registry[B]) Bind(flowID int64, sel Selection) (B, error) {
	backend, err := r.Backend(sel.Kind())
	if err != nil {
		return backend, err
	}

	r.mx.Lock()
	r.flows[flowID] = sel.Kind()
	r.mx.Unlock()

	return backend, nil
}

// ForFlow treats a flow that is unbound in this process and gone from the database as Docker, like every flow without a stored selection.
func (r *Registry[B]) ForFlow(ctx context.Context, flowID int64) (B, error) {
	r.mx.RLock()
	kind, ok := r.flows[flowID]
	r.mx.RUnlock()
	if ok {
		return r.Backend(kind)
	}

	flow, err := r.db.GetFlow(ctx, flowID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return r.Backend(KindDocker)
		}
		var zero B
		return zero, fmt.Errorf("failed to read the sandbox of flow %d: %w", flowID, err)
	}

	sel, err := SelectionFromFunctions(flow.Functions)
	if err != nil {
		var zero B
		return zero, err
	}

	return r.Bind(flowID, sel)
}
