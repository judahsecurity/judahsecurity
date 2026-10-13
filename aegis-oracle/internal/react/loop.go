package react

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/your-org/aegis-oracle/pkg/module"
	"github.com/your-org/aegis-oracle/pkg/schema"
)

// MaxIterations is the default iteration budget.
const MaxIterations = 10

// ─────────────────────────── State types ────────────────────────────────────

// TraceStep records one Thought → Action → Observation cycle.
type TraceStep struct {
	Iteration   int
	Thought     string
	ToolName    string         // empty on final_answer
	ToolArgs    map[string]any // empty on final_answer
	Observation string         // tool output or error text
	ElapsedMS   int64
}

// Decision is the structured JSON the LLM emits on each iteration.
type Decision struct {
	Thought     string         `json:"thought"`
	Action      string         `json:"action"` // "use_tool" | "final_answer"
	ToolName    string         `json:"tool_name"`
	ToolArgs    map[string]any `json:"tool_args"`
	FinalAnswer *FinalAnswer   `json:"final_answer"`
}

// FinalAnswer is the terminal output of a completed loop.
type FinalAnswer struct {
	Summary string          `json:"summary"`
	Finding *schema.Finding `json:"finding"` // nil if no analysis was run
}

// LoopResult is returned to the caller after the loop terminates.
type LoopResult struct {
	Answer     string
	Finding    *schema.Finding
	Trace      []TraceStep
	Iterations int
	ElapsedMS  int64
}

// ChatTurn supplies recent context for a follow-up question. The loop still
// rechecks findings with its tools before treating them as current evidence.
type ChatTurn struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ─────────────────────────── Loop ───────────────────────────────────────────

// Loop runs the Oracle ReAct harness for a single user question.
//
// Each iteration:
//  1. Builds the system prompt with the current trace
//  2. Calls the LLM for a Decision (always JSON)
//  3. If action == "use_tool": runs the tool, appends observation, loops
//  4. If action == "final_answer": terminates and returns LoopResult
//
// The loop is bounded by maxIterations to prevent runaway costs.
// On budget exhaustion it synthesises a best-effort answer from the trace.
type Loop struct {
	llm           module.LLMProvider
	tools         *Registry
	maxIterations int
	model         string
	maxTokens     int
}

// Config configures the Loop.
type Config struct {
	LLM           module.LLMProvider
	Tools         *Registry
	MaxIterations int    // 0 → DefaultMaxIterations
	Model         string // empty → provider default
	MaxTokens     int    // 0 → 2048
}

// New creates a Loop from the provided config.
func New(cfg Config) *Loop {
	max := cfg.MaxIterations
	if max <= 0 {
		max = MaxIterations
	}
	toks := cfg.MaxTokens
	if toks <= 0 {
		toks = 2048
	}
	return &Loop{
		llm:           cfg.LLM,
		tools:         cfg.Tools,
		maxIterations: max,
		model:         cfg.Model,
		maxTokens:     toks,
	}
}

// Run executes the ReAct loop for the given user question.
// It is safe to call concurrently — no shared mutable state.
func (l *Loop) Run(ctx context.Context, question string) (*LoopResult, error) {
	return l.RunWithHistory(ctx, question, nil)
}

// RunWithHistory executes the ReAct loop with bounded conversation context.
func (l *Loop) RunWithHistory(ctx context.Context, question string, history []ChatTurn) (*LoopResult, error) {
	start := time.Now()
	var trace []TraceStep
	var lastFinding *schema.Finding

	slog.Info("oracle react loop start", "question", question, "max_iter", l.maxIterations)

	for iter := 0; iter < l.maxIterations; iter++ {
		iterStart := time.Now()

		system := buildSystemPrompt(l.tools, trace, l.maxIterations)
		user := buildUserPrompt(question, iter, history)

		resp, err := l.llm.CompleteJSON(ctx, module.JSONRequest{
			Model:     l.model,
			System:    system,
			User:      user,
			Schema:    decisionSchema,
			MaxTokens: l.maxTokens,
		})
		if err != nil {
			return nil, fmt.Errorf("react iter %d llm: %w", iter, err)
		}

		var decision Decision
		if err := json.Unmarshal([]byte(resp.Content), &decision); err != nil {
			// Malformed JSON — treat as a loop error and append an error step
			slog.Warn("react: malformed LLM decision", "iter", iter, "raw", resp.Content)
			trace = append(trace, TraceStep{
				Iteration:   iter,
				Thought:     "(parse error)",
				Observation: fmt.Sprintf("LLM returned unparseable JSON: %v", err),
				ElapsedMS:   time.Since(iterStart).Milliseconds(),
			})
			continue
		}

		slog.Debug("react decision", "iter", iter, "action", decision.Action, "tool", decision.ToolName)

		switch decision.Action {
		case "use_tool":
			observation, toolErr := l.runTool(ctx, decision.ToolName, decision.ToolArgs)

			// If the run_analysis tool returned a finding, capture it.
			if decision.ToolName == "run_analysis" {
				if f := extractFindingFromObs(observation); f != nil {
					lastFinding = f
				}
			}

			trace = append(trace, TraceStep{
				Iteration:   iter,
				Thought:     decision.Thought,
				ToolName:    decision.ToolName,
				ToolArgs:    decision.ToolArgs,
				Observation: observation,
				ElapsedMS:   time.Since(iterStart).Milliseconds(),
			})

			if toolErr != nil {
				slog.Warn("react: tool error", "tool", decision.ToolName, "error", toolErr)
				// Loop continues — LLM will see the error in next iteration.
			}

		case "final_answer":
			if decision.FinalAnswer == nil {
				decision.FinalAnswer = &FinalAnswer{Summary: "(no summary provided)"}
			}
			trace = append(trace, TraceStep{
				Iteration: iter,
				Thought:   decision.Thought,
				ElapsedMS: time.Since(iterStart).Milliseconds(),
			})

			// Prefer an explicitly returned finding over the captured one.
			finding := decision.FinalAnswer.Finding
			if finding == nil {
				finding = lastFinding
			}

			slog.Info("oracle react loop complete",
				"iterations", iter+1,
				"has_finding", finding != nil,
				"elapsed_ms", time.Since(start).Milliseconds())

			return &LoopResult{
				Answer:     decision.FinalAnswer.Summary,
				Finding:    finding,
				Trace:      trace,
				Iterations: iter + 1,
				ElapsedMS:  time.Since(start).Milliseconds(),
			}, nil

		default:
			// Unknown action — log and continue so LLM can self-correct.
			slog.Warn("react: unknown action", "iter", iter, "action", decision.Action)
			trace = append(trace, TraceStep{
				Iteration:   iter,
				Thought:     decision.Thought,
				Observation: fmt.Sprintf("Unknown action %q — valid values are 'use_tool' and 'final_answer'", decision.Action),
				ElapsedMS:   time.Since(iterStart).Milliseconds(),
			})
		}
	}

	// Budget exhausted — synthesise a best-effort answer from the trace.
	slog.Warn("react: iteration budget exhausted", "max", l.maxIterations)
	return &LoopResult{
		Answer:     buildBudgetExhaustedAnswer(trace),
		Finding:    lastFinding,
		Trace:      trace,
		Iterations: l.maxIterations,
		ElapsedMS:  time.Since(start).Milliseconds(),
	}, nil
}

// ─────────────────────────── helpers ─────────────────────────────────────

func (l *Loop) runTool(ctx context.Context, name string, args map[string]any) (string, error) {
	if args == nil {
		args = map[string]any{}
	}
	tool, ok := l.tools.Get(name)
	if !ok {
		return fmt.Sprintf("unknown tool %q — available tools: %v", name, toolNames(l.tools)), nil
	}
	out, err := tool.Run(ctx, args)
	if err != nil {
		return fmt.Sprintf("tool %q error: %v", name, err), err
	}
	return out, nil
}

func toolNames(reg *Registry) []string {
	out := make([]string, 0, len(reg.order))
	for _, n := range reg.order {
		out = append(out, n)
	}
	return out
}

func buildUserPrompt(question string, iter int, history []ChatTurn) string {
	if len(history) == 0 {
		if iter == 0 {
			return question
		}
		return fmt.Sprintf("[Iteration %d] Continue working on: %s", iter+1, question)
	}
	if len(history) > 6 {
		history = history[len(history)-6:]
	}
	var b strings.Builder
	b.WriteString("Previous conversation for reference. Verify current findings with tools before answering.\n")
	for _, turn := range history {
		if turn.Role != "user" && turn.Role != "assistant" {
			continue
		}
		content := []rune(strings.TrimSpace(turn.Content))
		if len(content) > 2000 {
			content = content[:2000]
		}
		encoded, _ := json.Marshal(string(content))
		fmt.Fprintf(&b, "%s: %s\n", turn.Role, encoded)
	}
	if iter > 0 {
		fmt.Fprintf(&b, "[Iteration %d] ", iter+1)
	}
	fmt.Fprintf(&b, "Current question: %s", question)
	return b.String()
}

func buildBudgetExhaustedAnswer(trace []TraceStep) string {
	if len(trace) == 0 {
		return "Analysis did not complete — no observations collected."
	}
	last := trace[len(trace)-1]
	if last.Observation != "" {
		return fmt.Sprintf("Analysis reached iteration budget. Last observation: %s", last.Observation)
	}
	return "Analysis reached the iteration budget before producing a final answer. Review the execution trace for partial results."
}

// extractFindingFromObs attempts to extract a serialised schema.Finding
// from a run_analysis tool observation. The tool embeds it as JSON.
func extractFindingFromObs(obs string) *schema.Finding {
	var wrapper struct {
		Finding *schema.Finding `json:"finding"`
	}
	if err := json.Unmarshal([]byte(obs), &wrapper); err != nil {
		return nil
	}
	return wrapper.Finding
}

// ─────────────────────────── JSON schema for LLM output ─────────────────────

// decisionSchema is passed to LLMProvider.CompleteJSON as the expected
// output shape. Providers that support schema enforcement (Anthropic
// tool_use, OpenAI response_format) will constrain the output to this.
var decisionSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"thought":   map[string]any{"type": "string"},
		"action":    map[string]any{"type": "string", "enum": []string{"use_tool", "final_answer"}},
		"tool_name": map[string]any{"type": "string"},
		"tool_args": map[string]any{"type": "object"},
		"final_answer": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"summary": map[string]any{"type": "string"},
				"finding": map[string]any{"type": "object"},
			},
		},
	},
	"required": []string{"thought", "action"},
}
