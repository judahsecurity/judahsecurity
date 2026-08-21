"""
Agent State Models

Pydantic models and TypedDict definitions for the AI agent state machine.
"""

import json
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Literal, TypedDict
from pydantic import BaseModel, Field, field_validator


def utc_now() -> datetime:
    """Get current UTC timestamp."""
    return datetime.now(timezone.utc)


def clip_text(value: Any, limit: int) -> str:
    """Slice a value that may be None / non-str without raising TypeError.

    ``dict.get("k", "")[:n]`` still crashes when the key exists and is ``None``
    — that is the Agent page ``'NoneType' object is not subscriptable`` error.
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    if limit < 0:
        return value
    return value[:limit]


# Type aliases
Phase = Literal["informational", "exploitation", "post_exploitation"]
ActionType = Literal["use_tool", "complete", "transition_phase", "ask_user"]


class ExtractedTargetInfo(BaseModel):
    """Information extracted from tool outputs."""
    primary_target: Optional[str] = None
    ports: List[int] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    technologies: List[str] = Field(default_factory=list)
    vulnerabilities: List[str] = Field(default_factory=list)
    credentials: List[Dict[str, Any]] = Field(default_factory=list)
    sessions: List[int] = Field(default_factory=list)


class TargetInfo(BaseModel):
    """Accumulated target information across all steps."""
    primary_target: Optional[str] = None
    ports: List[int] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    technologies: List[str] = Field(default_factory=list)
    vulnerabilities: List[str] = Field(default_factory=list)
    credentials: List[Dict[str, Any]] = Field(default_factory=list)
    sessions: List[int] = Field(default_factory=list)
    
    def merge_from(self, other: "TargetInfo") -> "TargetInfo":
        """Merge another TargetInfo into this one, preserving unique values."""
        return TargetInfo(
            primary_target=other.primary_target or self.primary_target,
            ports=list(set(self.ports + other.ports)),
            services=list(set(self.services + other.services)),
            technologies=list(set(self.technologies + other.technologies)),
            vulnerabilities=list(set(self.vulnerabilities + other.vulnerabilities)),
            credentials=self.credentials + other.credentials,
            sessions=list(set(self.sessions + other.sessions)),
        )


class TodoItem(BaseModel):
    """A todo item in the agent's task list."""
    description: str
    status: Literal["pending", "in_progress", "completed", "blocked"] = "pending"
    priority: Literal["high", "medium", "low"] = "medium"


class ExecutionStep(BaseModel):
    """A single step in the agent's execution trace."""
    iteration: int
    phase: Phase
    thought: str
    reasoning: str
    tool_name: Optional[str] = None
    tool_args: Optional[Dict[str, Any]] = None
    tool_output: Optional[str] = None
    success: Optional[bool] = None
    error_message: Optional[str] = None
    output_analysis: Optional[str] = None
    actionable_findings: List[str] = Field(default_factory=list)
    recommended_next_steps: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=utc_now)
    token_usage: Optional[Dict[str, Any]] = None
    llm_model: Optional[str] = None


class PhaseTransitionRequest(BaseModel):
    """Request for phase transition requiring approval."""
    from_phase: Phase
    to_phase: Phase
    reason: str
    planned_actions: List[str] = Field(default_factory=list)
    risks: List[str] = Field(default_factory=list)


class PhaseHistoryEntry(BaseModel):
    """Entry in the phase transition history."""
    phase: Phase
    entered_at: datetime = Field(default_factory=utc_now)


class UserQuestionRequest(BaseModel):
    """Request for user input/clarification."""
    question: str
    context: Optional[str] = None
    format: Literal["text", "single_choice", "multi_choice"] = "text"
    options: Optional[List[str]] = None
    default_value: Optional[str] = None
    phase: Phase = "informational"
    question_id: str = Field(default_factory=lambda: str(utc_now().timestamp()))


class UserQuestionAnswer(BaseModel):
    """User's answer to a question."""
    question_id: str
    answer: str


class QAHistoryEntry(BaseModel):
    """Q&A exchange history entry."""
    question: UserQuestionRequest
    answer: Optional[UserQuestionAnswer] = None
    answered_at: Optional[datetime] = None


class UserQuestion(BaseModel):
    """User question specification for LLM decision."""
    question: str
    context: Optional[str] = None
    format: Literal["text", "single_choice", "multi_choice"] = "text"
    options: Optional[List[str]] = None
    default_value: Optional[str] = None


class PhaseTransition(BaseModel):
    """Phase transition specification for LLM decision."""
    to_phase: Phase
    reason: str
    planned_actions: List[str] = Field(default_factory=list)
    risks: List[str] = Field(default_factory=list)


class LLMDecision(BaseModel):
    """Structured decision from the LLM."""
    thought: str
    reasoning: str
    action: ActionType
    tool_name: Optional[str] = None
    tool_args: Optional[Dict[str, Any]] = None
    phase_transition: Optional[PhaseTransition] = None
    user_question: Optional[UserQuestion] = None
    completion_reason: Optional[str] = None
    updated_todo_list: List[TodoItem] = Field(default_factory=list)

    @field_validator("thought", "reasoning", mode="before")
    @classmethod
    def coerce_thought_reasoning(cls, v: Any) -> str:
        if v is None:
            return ""
        if isinstance(v, str):
            return v
        return str(v)

    @field_validator("tool_args", mode="before")
    @classmethod
    def coerce_tool_args(cls, v: Any) -> Optional[Dict[str, Any]]:
        """Local models often emit tool_args as a bare CLI string or nested oddly."""
        if v is None or v == "":
            return None
        if isinstance(v, dict):
            return v
        if isinstance(v, str):
            s = v.strip()
            if not s:
                return {}
            # JSON object string
            if s.startswith("{"):
                try:
                    parsed = json.loads(s)
                    if isinstance(parsed, dict):
                        return parsed
                except Exception:
                    pass
            return {"args": s}
        if isinstance(v, list):
            return {"args": " ".join(str(x) for x in v)}
        return {"args": str(v)}


class OutputAnalysis(BaseModel):
    """Analysis of tool output by the LLM."""
    interpretation: str = ""
    extracted_info: ExtractedTargetInfo = Field(default_factory=ExtractedTargetInfo)
    actionable_findings: List[str] = Field(default_factory=list)
    recommended_next_steps: List[str] = Field(default_factory=list)

    @field_validator("interpretation", mode="before")
    @classmethod
    def coerce_interpretation(cls, v: Any) -> str:
        if v is None:
            return ""
        if isinstance(v, str):
            return v
        return str(v)


class ConversationObjective(BaseModel):
    """A single objective in a multi-objective conversation."""
    content: str
    required_phase: Phase = "informational"
    created_at: datetime = Field(default_factory=utc_now)
    completed_at: Optional[datetime] = None
    completion_reason: Optional[str] = None


class ObjectiveOutcome(BaseModel):
    """Outcome of a completed objective."""
    objective: ConversationObjective
    execution_steps: List[str] = Field(default_factory=list)
    findings: Dict[str, Any] = Field(default_factory=dict)
    success: bool = False


class InvokeResponse(BaseModel):
    """Response from agent invocation."""
    answer: str = ""
    tool_used: Optional[str] = None
    tool_output: Optional[str] = None
    current_phase: Phase = "informational"
    iteration_count: int = 0
    task_complete: bool = False
    todo_list: List[Dict[str, Any]] = Field(default_factory=list)
    execution_trace_summary: str = ""
    awaiting_approval: bool = False
    approval_request: Optional[Dict[str, Any]] = None
    awaiting_question: bool = False
    question_request: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    # Soft notice when preferred LLM was unavailable but a fallback kept serving
    warning: Optional[str] = None
    engagement_replay: List[Dict[str, Any]] = Field(default_factory=list)
    token_usage: Optional[Dict[str, Any]] = None
    cost_usd: Optional[float] = None
    price_limit_usd: Optional[float] = None
    compacted: bool = False


class AgentState(TypedDict, total=False):
    """Agent state for LangGraph."""
    # Core state
    messages: List[Any]
    current_iteration: int
    max_iterations: int
    current_phase: Phase
    task_complete: bool
    completion_reason: Optional[str]
    
    # Execution tracking
    execution_trace: List[Dict[str, Any]]
    todo_list: List[Dict[str, Any]]
    target_info: Dict[str, Any]
    phase_history: List[Dict[str, Any]]
    
    # Multi-objective support
    conversation_objectives: List[Dict[str, Any]]
    current_objective_index: int
    objective_history: List[Dict[str, Any]]
    original_objective: str  # Backward compatibility
    
    # Q&A support
    qa_history: List[Dict[str, Any]]
    pending_question: Optional[Dict[str, Any]]
    awaiting_user_question: bool
    user_question_answer: Optional[str]
    
    # Approval flow
    phase_transition_pending: Optional[Dict[str, Any]]
    awaiting_user_approval: bool
    user_approval_response: Optional[str]
    user_modification: Optional[str]
    
    # Tenant context
    user_id: str
    project_id: str
    session_id: str
    organization_id: Optional[int]
    
    # Mode: assist (approval required) | agent (autonomous)
    mode: Optional[str]
    
    # Initial input (playbook)
    initial_todos: Optional[List[Dict[str, Any]]]

    # Browser walkthrough → structured application understanding
    capability_map: Optional[Dict[str, Any]]
    # Authenticated browser session handoff (storage_state / cookies)
    auth_session: Optional[Dict[str, Any]]
    # Tester-process control plane (hypotheses, creds, approaches, chains)
    engagement_brain: Optional[Dict[str, Any]]

    # Fast URL kickoff (robots / key paths) — injected before first LLM think
    kickoff_brief: Optional[str]
    # Early-queued Interceptor job id (agent attaches instead of double-crawl)
    interceptor_job_id: Optional[str]
    # Parallel recon stream briefs drained into the prompt (Copilot-style)
    recon_worker_briefs: Optional[List[str]]
    # Kickoff saw 404/empty root — directory brute-force is mandatory
    needs_dir_brute: Optional[bool]
    
    # Internal state
    _current_step: Optional[Dict[str, Any]]
    _decision: Optional[Dict[str, Any]]
    _tool_result: Optional[Dict[str, Any]]
    _just_transitioned_to: Optional[Phase]
    _emitted_approval_key: Optional[str]
    _emitted_question_key: Optional[str]
    token_usage: Optional[Dict[str, Any]]
    operator_steers: Optional[List[str]]
    prior_hunt_brief: Optional[str]
    compacted_brief: Optional[str]
    price_limit_usd: Optional[float]


def format_todo_list(todo_list: List[Dict[str, Any]]) -> str:
    """Format todo list for prompt inclusion."""
    if not todo_list:
        return "No tasks defined yet."
    
    lines = []
    for todo in todo_list:
        if not isinstance(todo, dict):
            continue
        status_icon = {
            "pending": "[ ]",
            "in_progress": "[~]",
            "completed": "[x]",
            "blocked": "[!]"
        }.get(todo.get("status") or "pending", "[ ]")
        priority = todo.get("priority") or "medium"
        priority_marker = {"high": "!!!", "medium": "!!", "low": "!"}.get(priority, "!!")
        lines.append(f"{status_icon} {priority_marker} {todo.get('description') or ''}")
    
    return "\n".join(lines) or "No tasks defined yet."


def format_execution_trace(
    trace: List[Dict[str, Any]],
    objectives: List[Dict[str, Any]] = None,
    objective_history: List[Dict[str, Any]] = None,
    current_objective_index: int = 0,
    max_steps: int = 10
) -> str:
    """Format execution trace for prompt inclusion."""
    if not trace:
        return "No steps executed yet."
    
    # Show last N steps
    recent_trace = trace[-max_steps:]
    
    lines = []
    for step in recent_trace:
        if not isinstance(step, dict):
            continue
        iteration = step.get("iteration", 0)
        phase = step.get("phase") or "informational"
        thought = clip_text(step.get("thought"), 200)
        tool_name = step.get("tool_name") or ""
        success = step.get("success")
        analysis = clip_text(step.get("output_analysis"), 300)
        
        lines.append(f"## Step {iteration} [{phase}]")
        lines.append(f"Thought: {thought}")
        if tool_name:
            status = "✓" if success else "✗" if success is False else "?"
            lines.append(f"Tool: {tool_name} [{status}]")
            if analysis:
                lines.append(f"Analysis: {analysis}")
        lines.append("")
    
    return "\n".join(lines) or "No steps executed yet."


def format_qa_history(qa_history: List[Dict[str, Any]]) -> str:
    """Format Q&A history for prompt inclusion."""
    if not qa_history:
        return "No Q&A history."
    
    lines = []
    for i, entry in enumerate(qa_history, 1):
        if not isinstance(entry, dict):
            continue
        question = entry.get("question") or {}
        answer = entry.get("answer") or {}
        if not isinstance(question, dict):
            question = {}
        if not isinstance(answer, dict):
            answer = {}
        q_text = clip_text(question.get("question") or "Unknown question", 200)
        a_text = clip_text(answer.get("answer") or "Awaiting answer", 200) if entry.get("answer") else "Awaiting answer"
        lines.append(f"Q{i}: {q_text}")
        lines.append(f"A{i}: {a_text}")
        lines.append("")
    
    return "\n".join(lines) or "No Q&A history."


def format_objective_history(objective_history: List[Dict[str, Any]]) -> str:
    """Format objective history for prompt inclusion."""
    if not objective_history:
        return "No completed objectives."
    
    lines = []
    for i, outcome in enumerate(objective_history, 1):
        if not isinstance(outcome, dict):
            continue
        obj = outcome.get("objective") or {}
        if not isinstance(obj, dict):
            obj = {}
        success = outcome.get("success", False)
        status = "✓" if success else "✗"
        content = clip_text(obj.get("content") or "Unknown objective", 100)
        lines.append(f"{i}. [{status}] {content}")
    
    return "\n".join(lines) or "No completed objectives."


def summarize_trace_for_response(trace: List[Dict[str, Any]]) -> str:
    """Create a brief summary of the execution trace for responses."""
    if not trace:
        return "No actions taken."
    
    tools_used = []
    findings = []
    
    for step in trace:
        if not isinstance(step, dict):
            continue
        if step.get("tool_name"):
            tools_used.append(step["tool_name"])
        for finding in step.get("actionable_findings") or []:
            findings.append(finding)
    
    summary_parts = []
    if tools_used:
        unique_tools = list(dict.fromkeys(tools_used))  # Preserve order, remove dups
        summary_parts.append(f"Tools used: {', '.join(unique_tools[:5])}")
    if findings:
        summary_parts.append(f"Key findings: {len(findings)} actionable items")
    
    return "; ".join(summary_parts) if summary_parts else "Analysis complete."


def migrate_legacy_objective(state: AgentState) -> AgentState:
    """Migrate legacy single-objective state to multi-objective format."""
    if state.get("conversation_objectives"):
        return state  # Already migrated
    
    # Create objective from original_objective
    original = state.get("original_objective", "")
    if original:
        state["conversation_objectives"] = [
            ConversationObjective(content=original).model_dump()
        ]
        state["current_objective_index"] = 0
        state["objective_history"] = []
    
    return state
