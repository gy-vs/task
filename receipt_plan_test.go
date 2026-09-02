package task_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-task/task/v3"
	"github.com/go-task/task/v3/internal/filepathext"
	"github.com/go-task/task/v3/receipt"
	"github.com/go-task/task/v3/taskfile/ast"
)

const receiptFixtureDir = "testdata/receipt"

func receiptExecutor(t *testing.T, dir string) *task.Executor {
	t.Helper()
	buff := bytes.NewBuffer(nil)
	e := task.NewExecutor(
		task.WithDir(dir),
		task.WithTempDir(task.TempDir{
			Remote:      filepathext.SmartJoin(dir, ".task"),
			Fingerprint: filepathext.SmartJoin(dir, ".task"),
		}),
		task.WithStdout(buff),
		task.WithStderr(buff),
	)
	require.NoError(t, e.Setup())
	return e
}

func generateReceipt(t *testing.T, dir string, calls ...*task.Call) (*task.Executor, *receipt.Receipt) {
	t.Helper()
	e := receiptExecutor(t, dir)
	r, err := e.GenerateReceipt(context.Background(), calls...)
	require.NoError(t, err)
	return e, r
}

func TestReceiptGenerate(t *testing.T) {
	t.Parallel()

	_, r := generateReceipt(t, receiptFixtureDir, &task.Call{Task: "default"})

	require.Equal(t, receipt.FormatName, r.Format)
	require.Equal(t, receipt.Version, r.Version)
	assert.Equal(t, []string{"default"}, r.Entries)
	assert.Len(t, r.Fingerprint, 64, "fingerprint must be a sha256 hex digest")

	// Includes: the lib include is recorded with both Taskfiles.
	require.Len(t, r.Includes, 1)
	inc := r.Includes[0]
	assert.Equal(t, "lib", inc.Namespace)
	assert.Equal(t, "Taskfile.yml", inc.Parent)
	assert.Equal(t, filepath.ToSlash("included/Taskfile.yml"), inc.Target)

	// Plan order: dependencies before the tasks that require them, task
	// calls from commands in command order, entries last.
	gotPlan := make([][2]string, 0, len(r.Plan))
	for _, s := range r.Plan {
		assert.NotEmpty(t, s.Digest, "plan step must carry a task digest")
		gotPlan = append(gotPlan, [2]string{s.Task, s.Via})
	}
	wantPlan := [][2]string{
		{"lib:setup", "dep"},
		{"gen", "dep"},
		{"build", "dep"},
		{"package", "cmd"},
		{"lib:setup", "cmd"},
		{"default", "entry"},
	}
	assert.Equal(t, wantPlan, gotPlan)

	// Every task in the plan has a descriptor with its Taskfile of origin.
	byName := make(map[string]receipt.Task, len(r.Tasks))
	for _, task := range r.Tasks {
		byName[task.Name] = task
	}
	require.Contains(t, byName, "build")
	require.Contains(t, byName, "gen")
	require.Contains(t, byName, "package")
	require.Contains(t, byName, "default")
	require.Contains(t, byName, "lib:setup")

	build := byName["build"]
	assert.Equal(t, []string{"b"}, build.Aliases)
	assert.Equal(t, "Taskfile.yml", build.Taskfile)
	assert.Equal(t, []string{"lib:setup", "gen"}, build.Deps)
	require.Len(t, build.Cmds, 3)
	assert.Equal(t, "task", build.Cmds[2].Kind)
	assert.Equal(t, "package", build.Cmds[2].Task)

	libSetup := byName["lib:setup"]
	assert.Equal(t, filepath.ToSlash("included/Taskfile.yml"), libSetup.Taskfile)

	// Variables: provenance is recorded without raw values.
	var mode, greeting, secret *receipt.Var
	for i := range r.Vars {
		v := &r.Vars[i]
		switch {
		case v.Task == "gen" && v.Name == "MODE":
			mode = v
		case v.Task == "" && v.Name == "GREETING":
			greeting = v
		case v.Task == "" && v.Name == "SECRET_TOKEN":
			secret = v
		}
	}
	require.NotNil(t, mode, "dep variable MODE must be recorded")
	assert.Equal(t, "call", mode.Source)
	assert.NotEmpty(t, mode.Digest)
	require.NotNil(t, greeting)
	assert.Equal(t, "taskfile-vars", greeting.Source)
	assert.Equal(t, "static", greeting.Kind)
	require.NotNil(t, secret)
	assert.Equal(t, "dynamic", secret.Kind)
	assert.True(t, secret.Secret)
	assert.NotEmpty(t, secret.Digest)

	// Sources summary uses the same glob expansion as fingerprinting.
	var genSources *receipt.Sources
	for i := range r.Sources {
		if r.Sources[i].Task == "gen" {
			genSources = &r.Sources[i]
		}
	}
	require.NotNil(t, genSources)
	assert.Equal(t, []string{"src/*.txt"}, genSources.Globs)
	assert.Equal(t, []string{filepath.ToSlash("src/a.txt")}, genSources.Files)
	assert.NotEmpty(t, genSources.Digest)
}

func TestReceiptRedaction(t *testing.T) {
	t.Parallel()

	e, r := generateReceipt(t, receiptFixtureDir, &task.Call{Task: "default"})

	// Pass a CLI variable like the CLI would; its raw value must not be
	// written anywhere.
	globals := ast.NewVars()
	globals.Set("MY_CLI_VAR", ast.Var{Value: "cli-secret-value-xyz"})
	e.Taskfile.Vars.Merge(globals, nil)
	e.Options(task.WithGlobalVars(globals))
	r2, err := e.GenerateReceipt(context.Background(), &task.Call{Task: "default"})
	require.NoError(t, err)

	raw := marshalReceipt(t, r2)
	assert.NotContains(t, raw, "fakesecret12345", "dynamic secret value must be redacted")
	assert.NotContains(t, raw, "cli-secret-value-xyz", "CLI variable value must be redacted")
	assert.NotContains(t, raw, e.Dir, "absolute checkout path must not appear")
	assert.Contains(t, raw, "*****", "redaction marker expected in masked commands")
	_ = marshalReceipt(t, r)
}

func TestReceiptDeterministicAcrossPaths(t *testing.T) {
	t.Parallel()

	dirA := filepath.Join(t.TempDir(), "checkout-a")
	dirB := filepath.Join(t.TempDir(), "checkout-b")
	copyFixtureDir(t, receiptFixtureDir, dirA)
	copyFixtureDir(t, receiptFixtureDir, dirB)

	_, ra := generateReceipt(t, dirA, &task.Call{Task: "default"})
	_, rb := generateReceipt(t, dirB, &task.Call{Task: "default"})

	assert.Equal(t, marshalReceipt(t, ra), marshalReceipt(t, rb),
		"same commit and inputs must produce byte-identical receipts regardless of checkout path")
	assert.Equal(t, ra.Fingerprint, rb.Fingerprint)
}

func TestReceiptAliasEntry(t *testing.T) {
	t.Parallel()

	_, r := generateReceipt(t, receiptFixtureDir, &task.Call{Task: "b"})
	assert.Equal(t, []string{"b"}, r.Entries)

	var buildStep *receipt.Step
	for i := range r.Plan {
		if r.Plan[i].Task == "build" && r.Plan[i].Via == "entry" {
			buildStep = &r.Plan[i]
		}
	}
	require.NotNil(t, buildStep, "alias must resolve to the build task as an entry step")
	assert.Equal(t, "b", buildStep.Call, "invoked alias must be preserved on the step")
}

func TestReceiptPlatformSkip(t *testing.T) {
	t.Parallel()

	_, r := generateReceipt(t, receiptFixtureDir, &task.Call{Task: "platonly"})
	require.Len(t, r.Plan, 1)
	assert.Equal(t, "platonly", r.Plan[0].Task)
	assert.Equal(t, "platform", r.Plan[0].Skipped)

	for _, task := range r.Tasks {
		if task.Name == "platonly" {
			assert.False(t, task.RunsOnPlatform)
			assert.NotEmpty(t, task.Platforms)
		}
	}
}

func TestReceiptCycle(t *testing.T) {
	t.Parallel()

	_, r := generateReceipt(t, "testdata/cyclic", &task.Call{Task: "task-1"})

	var cycles int
	for _, s := range r.Plan {
		if s.Cycle {
			cycles++
		}
	}
	assert.Greater(t, cycles, 0, "cyclic dependency must be recorded, not expanded forever")
	// Both tasks are still part of the plan and the walk terminates.
	names := map[string]bool{}
	for _, s := range r.Plan {
		names[s.Task] = true
	}
	assert.True(t, names["task-1"] && names["task-2"])
}

func TestReceiptCompareEqual(t *testing.T) {
	t.Parallel()

	_, r1 := generateReceipt(t, receiptFixtureDir, &task.Call{Task: "default"})
	_, r2 := generateReceipt(t, receiptFixtureDir, &task.Call{Task: "default"})

	diff, err := receipt.Compare(r1, r2)
	require.NoError(t, err)
	assert.True(t, diff.Equal)
}

func TestReceiptCompareDetectsStepChange(t *testing.T) {
	t.Parallel()

	_, ra := generateReceipt(t, receiptFixtureDir, &task.Call{Task: "default"})

	dirB := filepath.Join(t.TempDir(), "changed")
	copyFixtureDir(t, receiptFixtureDir, dirB)
	taskfilePath := filepath.Join(dirB, "Taskfile.yml")
	b, err := os.ReadFile(taskfilePath)
	require.NoError(t, err)
	b = bytes.ReplaceAll(b, []byte(`echo "root default"`), []byte(`echo "root default changed"`))
	require.NoError(t, os.WriteFile(taskfilePath, b, 0o644))

	_, rb := generateReceipt(t, dirB, &task.Call{Task: "default"})

	diff, err := receipt.Compare(ra, rb)
	require.NoError(t, err)
	assert.False(t, diff.Equal)
	assert.NotEmpty(t, diff.Steps)
	var changed bool
	for _, sc := range diff.Steps {
		if sc.Kind == receipt.ChangeChanged && sc.TaskB == "default" {
			changed = true
		}
	}
	assert.True(t, changed, "a command change must be reported as a changed step")
}

func TestReceiptCompareDetectsVarChange(t *testing.T) {
	t.Parallel()

	_, ra := generateReceipt(t, receiptFixtureDir, &task.Call{Task: "default"})

	e := receiptExecutor(t, receiptFixtureDir)
	globals := ast.NewVars()
	globals.Set("MY_CLI_VAR", ast.Var{Value: "cli-secret-value-xyz"})
	e.Taskfile.Vars.Merge(globals, nil)
	e.Options(task.WithGlobalVars(globals))
	rb, err := e.GenerateReceipt(context.Background(), &task.Call{Task: "default"})
	require.NoError(t, err)

	diff, err := receipt.Compare(ra, rb)
	require.NoError(t, err)
	assert.False(t, diff.Equal)

	found := false
	for _, vc := range diff.Vars {
		if vc.Name == "MY_CLI_VAR" && vc.Kind == receipt.ChangeAdded {
			found = true
			assert.Equal(t, "cli", vc.B.Source)
			assert.True(t, vc.B.Secret)
		}
	}
	assert.True(t, found, "CLI variables must appear as var diffs with the cli source")
}

func TestReceiptReadUnsupportedVersion(t *testing.T) {
	t.Parallel()

	_, r := generateReceipt(t, receiptFixtureDir, &task.Call{Task: "default"})
	raw := marshalReceipt(t, r)

	var asMap map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw), &asMap))
	asMap["version"] = 999
	modified, err := json.Marshal(asMap)
	require.NoError(t, err)

	_, err = receipt.Read(bytes.NewReader(modified))
	var unsupported *receipt.UnsupportedVersionError
	require.ErrorAs(t, err, &unsupported)
	assert.Equal(t, 999, unsupported.Version)
}

func TestReceiptDefaultExecutionUnaffected(t *testing.T) {
	t.Parallel()

	// Generating a receipt must not execute or modify anything: the
	// fixture has no generated outputs and running it through the
	// receipt planner leaves no .task directory behind.
	dir := filepath.Join(t.TempDir(), "fixture")
	copyFixtureDir(t, receiptFixtureDir, dir)

	e := receiptExecutor(t, dir)
	_, err := e.GenerateReceipt(context.Background(), &task.Call{Task: "default"})
	require.NoError(t, err)

	_, err = os.Stat(filepath.Join(dir, ".task"))
	assert.True(t, os.IsNotExist(err), "receipt generation must not create fingerprint state")
}

func marshalReceipt(t *testing.T, r *receipt.Receipt) string {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, receipt.Write(&buf, r))
	return buf.String()
}

func copyFixtureDir(t *testing.T, src, dst string) {
	t.Helper()
	require.NoError(t, filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	}))
}
