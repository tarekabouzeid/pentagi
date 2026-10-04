// Package sandbox names the sandbox runtimes a flow's tools can run in and
// keeps track of which runtime each flow is bound to.
//
// A runtime is anything that satisfies the Docker exec, copy and lifecycle
// surface the tools were written against (docker.DockerClient). A non-Docker
// runtime adapts to that surface, so the terminal, file and flow-file code
// stays the same whatever the flow runs in.
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

// Selection is the runtime a flow was created with. It is persisted under
// "sandbox" in the flow's functions, so the binding survives a restart.
// An empty Backend is Docker, so a flow stored without a selection keeps
// running where it always ran. Profile is runtime specific; for OpenShell it
// names the policy preset.
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

// SelectionFromFunctions reads the "sandbox" key of a flow's stored
// functions without depending on the rest of their schema.
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

// Registry holds the enabled runtimes and the runtime of every flow it has
// seen. It is safe for concurrent use.
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

// Kinds lists the enabled runtimes, the default first.
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

// Select resolves a requested runtime against the enabled ones. A nil or
// empty request takes the default; the result always names its backend, so
// what is persisted does not depend on the default at the time it is read.
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

// Bind records the runtime of a flow, so later lookups skip the database.
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

// ForFlow returns the runtime a flow is bound to. A flow the database no
// longer returns (deleted) and was not bound in this process is taken to be a
// Docker flow, which is what every flow without a stored selection is.
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
