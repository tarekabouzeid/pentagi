package sandbox

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"

	"pentagi/pkg/database"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeRuntime struct{ name string }

type fakeFlows struct {
	mx    sync.Mutex
	flows map[int64]database.Flow
	err   error
	reads int
}

func (f *fakeFlows) GetFlow(ctx context.Context, id int64) (database.Flow, error) {
	if err := ctx.Err(); err != nil {
		return database.Flow{}, err
	}

	f.mx.Lock()
	defer f.mx.Unlock()

	f.reads++
	if f.err != nil {
		return database.Flow{}, f.err
	}
	flow, ok := f.flows[id]
	if !ok {
		return database.Flow{}, sql.ErrNoRows
	}
	return flow, nil
}

var (
	dockerRuntime    = &fakeRuntime{name: "docker"}
	openshellRuntime = &fakeRuntime{name: "openshell"}
)

func newBoth(t *testing.T, db flowReader, def Kind) *Registry[*fakeRuntime] {
	t.Helper()

	r, err := NewRegistry(db, def, map[Kind]*fakeRuntime{
		KindDocker:    dockerRuntime,
		KindOpenShell: openshellRuntime,
	})
	require.NoError(t, err)
	return r
}

func TestSandbox_NewRegistry_RefusesADefaultThatIsNotEnabled(t *testing.T) {
	_, err := NewRegistry(&fakeFlows{}, KindOpenShell, map[Kind]*fakeRuntime{KindDocker: dockerRuntime})
	require.ErrorIs(t, err, ErrUnavailable)

	_, err = NewRegistry(&fakeFlows{}, Kind("podman"), map[Kind]*fakeRuntime{KindDocker: dockerRuntime})
	require.ErrorContains(t, err, "unknown default sandbox backend 'podman'")
}

func TestSandbox_Kinds_ListsTheDefaultFirst(t *testing.T) {
	r := newBoth(t, &fakeFlows{}, KindOpenShell)

	assert.Equal(t, []Kind{"openshell", "docker"}, r.Kinds())
}

func TestSandbox_Select_ResolvesARequestAgainstTheEnabledRuntimes(t *testing.T) {
	dockerOnly, err := NewRegistry(&fakeFlows{}, KindDocker, map[Kind]*fakeRuntime{KindDocker: dockerRuntime})
	require.NoError(t, err)
	both := newBoth(t, &fakeFlows{}, KindOpenShell)

	tests := []struct {
		name      string
		registry  *Registry[*fakeRuntime]
		requested *Selection
		want      Selection
		wantErr   error
		wantText  string
	}{
		{name: "no request takes the default", registry: both, want: Selection{Backend: "openshell"}},
		{name: "an empty backend takes the default and keeps the profile", registry: both,
			requested: &Selection{Profile: "recon_only"}, want: Selection{Backend: "openshell", Profile: "recon_only"}},
		{name: "an enabled backend is kept", registry: both,
			requested: &Selection{Backend: "docker"}, want: Selection{Backend: "docker"}},
		{name: "a disabled backend is refused", registry: dockerOnly,
			requested: &Selection{Backend: "openshell"}, wantErr: ErrUnavailable},
		{name: "an unknown backend is refused", registry: both,
			requested: &Selection{Backend: "podman"}, wantText: "unknown sandbox backend 'podman'"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.registry.Select(tc.requested)
			switch {
			case tc.wantErr != nil:
				require.ErrorIs(t, err, tc.wantErr)
			case tc.wantText != "":
				require.ErrorContains(t, err, tc.wantText)
			default:
				require.NoError(t, err)
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

func TestSandbox_ForFlow_ReadsTheStoredSelectionOnce(t *testing.T) {
	db := &fakeFlows{flows: map[int64]database.Flow{
		7: {ID: 7, Functions: []byte(`{"sandbox":{"backend":"openshell","profile":"recon_only"}}`)},
	}}
	r := newBoth(t, db, KindDocker)

	for range 2 {
		got, err := r.ForFlow(context.Background(), 7)
		require.NoError(t, err)
		assert.Same(t, openshellRuntime, got)
	}
	assert.Equal(t, 1, db.reads, "a flow's runtime is read from the database once")
}

func TestSandbox_ForFlow_TakesAFlowWithoutASelectionToBeDocker(t *testing.T) {
	db := &fakeFlows{flows: map[int64]database.Flow{
		1: {ID: 1, Functions: []byte(`{}`)},
		2: {ID: 2},
	}}
	r := newBoth(t, db, KindOpenShell)

	for _, flowID := range []int64{1, 2, 3} {
		got, err := r.ForFlow(context.Background(), flowID)
		require.NoError(t, err, "flow %d", flowID)
		assert.Same(t, dockerRuntime, got, "flow %d", flowID)
	}
}

func TestSandbox_ForFlow_ReportsAFlowThatCannotBeRead(t *testing.T) {
	unreadable := errors.New("connection reset")
	r := newBoth(t, &fakeFlows{err: unreadable}, KindDocker)

	_, err := r.ForFlow(context.Background(), 1)
	require.ErrorIs(t, err, unreadable)

	broken := newBoth(t, &fakeFlows{flows: map[int64]database.Flow{1: {ID: 1, Functions: []byte(`{"sandbox":`)}}}, KindDocker)
	_, err = broken.ForFlow(context.Background(), 1)
	require.ErrorContains(t, err, "failed to read the sandbox of the flow functions")
}

func TestSandbox_ForFlow_RefusesAFlowBoundToARuntimeNoLongerEnabled(t *testing.T) {
	db := &fakeFlows{flows: map[int64]database.Flow{
		1: {ID: 1, Functions: []byte(`{"sandbox":{"backend":"openshell"}}`)},
	}}
	r, err := NewRegistry(db, KindDocker, map[Kind]*fakeRuntime{KindDocker: dockerRuntime})
	require.NoError(t, err)

	_, err = r.ForFlow(context.Background(), 1)
	require.ErrorIs(t, err, ErrUnavailable)
}

func TestSandbox_Bind_ServesTheFlowWithoutTheDatabase(t *testing.T) {
	db := &fakeFlows{}
	r := newBoth(t, db, KindDocker)

	bound, err := r.Bind(9, Selection{Backend: KindOpenShell})
	require.NoError(t, err)
	assert.Same(t, openshellRuntime, bound)

	got, err := r.ForFlow(context.Background(), 9)
	require.NoError(t, err)
	assert.Same(t, openshellRuntime, got)
	assert.Zero(t, db.reads)
}
