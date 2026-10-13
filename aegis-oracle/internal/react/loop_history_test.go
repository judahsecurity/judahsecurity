package react

import (
	"fmt"
	"strings"
	"testing"
)

func TestBuildUserPromptIncludesRecentContextAndCurrentQuestion(t *testing.T) {
	history := make([]ChatTurn, 0, 8)
	for i := 0; i < 8; i++ {
		role := "user"
		if i%2 == 1 {
			role = "assistant"
		}
		history = append(history, ChatTurn{Role: role, Content: fmt.Sprintf("turn %d", i)})
	}

	prompt := buildUserPrompt("Why is that finding high?", 0, history)
	if strings.Contains(prompt, "turn 0") || strings.Contains(prompt, "turn 1") {
		t.Fatal("prompt included turns outside the six-turn context window")
	}
	if !strings.Contains(prompt, `user: "turn 6"`) || !strings.Contains(prompt, `assistant: "turn 7"`) {
		t.Fatal("prompt omitted recent conversation context")
	}
	if !strings.Contains(prompt, "Current question: Why is that finding high?") {
		t.Fatal("prompt omitted the current question")
	}
	if !strings.Contains(prompt, "Verify current findings with tools") {
		t.Fatal("prompt did not ask Oracle to recheck findings")
	}
}
