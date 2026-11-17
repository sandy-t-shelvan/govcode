package app

import (
	"sort"

	"github.com/sandy-t-shelvan/govcode/internal/runstate"
	"github.com/sandy-t-shelvan/govcode/internal/tools"
)

func captureEnv(st *runstate.State, env *tools.Env) {
	st.Changed = changedPaths(env)
	st.EditGen, st.TestedGen, st.TestRuns, st.LastTestPass = env.EditGen, env.TestedGen, env.TestRuns, env.LastTestPass
	st.Plan = env.Plan
	st.MemoryLoaded = nil
	for d := range env.MemoryLoaded {
		st.MemoryLoaded = append(st.MemoryLoaded, d)
	}
	sort.Strings(st.MemoryLoaded)
	st.MemoryBudget = env.MemoryBudget
}

func restoreEnv(st *runstate.State, env *tools.Env) {
	env.Changed = map[string]bool{}
	for _, p := range st.Changed {
		env.Changed[p] = true
	}
	env.EditGen, env.TestedGen, env.TestRuns, env.LastTestPass = st.EditGen, st.TestedGen, st.TestRuns, st.LastTestPass
	env.Plan = st.Plan
	env.MemoryLoaded = map[string]bool{}
	for _, d := range st.MemoryLoaded {
		env.MemoryLoaded[d] = true
	}
	env.MemoryBudget = st.MemoryBudget
}
