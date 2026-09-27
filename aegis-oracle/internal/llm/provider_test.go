package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/your-org/aegis-oracle/internal/modules/reasoners/intrinsic/prompts"
	"github.com/your-org/aegis-oracle/pkg/module"
)

type stubProvider struct {
	model string
	err   error
	calls *int
}

func (s stubProvider) CompleteJSON(context.Context, module.JSONRequest) (module.JSONResponse, error) {
	*s.calls++
	if s.err != nil {
		return module.JSONResponse{}, s.err
	}
	return module.JSONResponse{Content: `{"ok":true}`, Model: s.model}, nil
}

func TestFallbackProviderTriesNextOnQuotaError(t *testing.T) {
	firstCalls := 0
	secondCalls := 0
	p := &fallbackProvider{providers: []namedProvider{
		{name: "anthropic", provider: stubProvider{err: fmt.Errorf("anthropic: HTTP 400: credit balance is too low"), calls: &firstCalls}},
		{name: "openai", provider: stubProvider{model: "gpt-test", calls: &secondCalls}},
	}}

	resp, err := p.CompleteJSON(context.Background(), module.JSONRequest{})
	if err != nil {
		t.Fatalf("expected fallback success, got %v", err)
	}
	if resp.Model != "gpt-test" {
		t.Fatalf("expected openai fallback model, got %q", resp.Model)
	}
	if firstCalls != 1 || secondCalls != 1 {
		t.Fatalf("expected both providers called once, got first=%d second=%d", firstCalls, secondCalls)
	}
}

func TestFallbackProviderReturnsClearErrorWhenAllFail(t *testing.T) {
	firstCalls := 0
	secondCalls := 0
	p := &fallbackProvider{providers: []namedProvider{
		{name: "anthropic", provider: stubProvider{err: fmt.Errorf("anthropic: HTTP 429: rate limit"), calls: &firstCalls}},
		{name: "openai", provider: stubProvider{err: fmt.Errorf("openai: HTTP 401: invalid key"), calls: &secondCalls}},
	}}

	_, err := p.CompleteJSON(context.Background(), module.JSONRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
	if got := err.Error(); got == "" || !containsAll(got, "LLM analysis could not be completed", "anthropic", "openai") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func containsAll(s string, needles ...string) bool {
	for _, n := range needles {
		if !strings.Contains(s, n) {
			return false
		}
	}
	return true
}

func TestOpenAISchemaMakesIntrinsicOptionalsNullable(t *testing.T) {
	var original map[string]any
	if err := json.Unmarshal([]byte(prompts.V1OutputSchema), &original); err != nil {
		t.Fatal(err)
	}
	converted, strict := openAISchema(original)
	if !strict {
		t.Fatal("intrinsic analysis schema should support strict output")
	}
	root := converted.(map[string]any)
	if _, ok := root["$schema"]; ok {
		t.Fatal("OpenAI schema must omit the JSON Schema draft declaration")
	}
	brief := root["properties"].(map[string]any)["analyst_brief"].(map[string]any)
	required := brief["required"].([]string)
	if !strings.Contains(strings.Join(required, ","), "not_affected_if") {
		t.Fatal("optional analyst brief field must be in required")
	}
	optional := brief["properties"].(map[string]any)["not_affected_if"].(map[string]any)
	types := optional["type"].([]string)
	if len(types) != 2 || types[0] != "string" || types[1] != "null" {
		t.Fatalf("optional field must accept null, got %v", types)
	}
	if _, ok := original["$schema"]; !ok {
		t.Fatal("conversion mutated the provider-neutral schema")
	}
}

func TestOpenAISchemaLeavesOpenAgentObjectsNonStrict(t *testing.T) {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"action":    map[string]any{"type": "string"},
			"tool_args": map[string]any{"type": "object"},
		},
	}
	_, strict := openAISchema(schema)
	if strict {
		t.Fatal("open tool arguments cannot use strict structured output")
	}
}
