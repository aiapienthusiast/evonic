"""Regression: assistant text recorded inside an open tool batch.

Live failure (session ``siwa-25ac767d``): the agent called ``send_file`` twice in
one parallel batch (a ``.jsonl.gz`` export). ``send_file`` echoes an assistant
``final`` row (the attachment note) at the moment the tool runs — *inside* the
still-open batch — so the transcript recorded

    tool_call(A), tool_call(B), final(text), tool_output(A), final(text), tool_output(B)

History reconstruction used to emit that assistant text in place, splitting the
declared calls from their results. ``_fix_interleaved_user_messages`` only
deferred user/system rows, so it fell back to injecting synthetic "interrupted"
results taken from a **set** — random order, and the real results were then
dropped as duplicates. ``validate_tool_pairs`` rejected the payload, and because
the row order is persisted, *every* later turn failed with a misleading
"exceeds this model's safe context budget" message (38k tokens against a 1M
window).

These tests pin the reconstruction contract:

* results follow their declaring message, in declared call order;
* real results survive (no synthetic replacement);
* deferred assistant text lands after the batch, never inside it;
* the outcome is independent of hash seed / insertion order;
* ``plan_request`` repairs such a payload instead of reporting a size verdict;
* the runtime defers the echo until the batch closes.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from models.chatlog import _fix_interleaved_user_messages, _reconstruct_llm_messages  # noqa: E402
from backend.agent_runtime.active_context import validate_tool_pairs  # noqa: E402
from backend.agent_runtime.request_budget import plan_request  # noqa: E402


def _batch_entries():
    """The exact 5-row shape from the incident (2 parallel calls + text)."""
    return [
        {'type': 'user', 'ts': 1, 'content': 'export both datasets'},
        {'type': 'tool_call', 'ts': 2, 'function': 'send_file',
         'params': {'file_path': '/tmp/a.jsonl.gz'}, 'id': 'call_A'},
        {'type': 'tool_call', 'ts': 3, 'function': 'send_file',
         'params': {'file_path': '/tmp/b.jsonl.gz'}, 'id': 'call_B'},
        {'type': 'final', 'ts': 4, 'content': '[File: a.jsonl.gz]',
         'metadata': {'attachment_info': {'filename': 'a.jsonl.gz'}}},
        {'type': 'tool_output', 'ts': 5, 'content': '{"ok": "sent-A"}',
         'tool_call_id': 'call_A', 'function': 'send_file'},
        {'type': 'final', 'ts': 6, 'content': '[File: b.jsonl.gz]',
         'metadata': {'attachment_info': {'filename': 'b.jsonl.gz'}}},
        {'type': 'tool_output', 'ts': 7, 'content': '{"ok": "sent-B"}',
         'tool_call_id': 'call_B', 'function': 'send_file'},
        {'type': 'final', 'ts': 8, 'content': 'both exports are ready'},
    ]


def _tool_ids(messages):
    return [m.get('tool_call_id') for m in messages if m.get('role') == 'tool']


def test_interleaved_batch_reconstructs_to_valid_protocol():
    messages = _reconstruct_llm_messages(_batch_entries())
    validate_tool_pairs(messages)  # strict: raises on out-of-order results
    assert _tool_ids(messages) == ['call_A', 'call_B']


def test_real_tool_results_survive_repair():
    messages = _reconstruct_llm_messages(_batch_entries())
    contents = [m['content'] for m in messages if m.get('role') == 'tool']
    assert contents == ['{"ok": "sent-A"}', '{"ok": "sent-B"}']
    assert not any('interrupted' in c for c in contents)


def test_deferred_assistant_text_lands_after_the_batch():
    messages = _reconstruct_llm_messages(_batch_entries())
    roles = [m['role'] for m in messages]
    # assistant(tool_calls) -> tool -> tool -> assistant text...
    first_tool = roles.index('tool')
    assert roles[first_tool - 1] == 'assistant'
    assert roles[first_tool + 1] == 'tool'
    assert roles[first_tool + 2] == 'assistant'
    texts = [m.get('content') for m in messages
             if m['role'] == 'assistant' and not m.get('tool_calls')]
    assert '[File: a.jsonl.gz]' in texts
    assert texts[-1] == 'both exports are ready'


def test_missing_outputs_are_synthesized_in_declared_order():
    """Synthetic results must follow declared order, not set-iteration order."""
    for ids in (
        ['call_00_ET_AiA', 'call_01_ET_8GP'],
        ['call_zz', 'call_aa', 'call_mm'],
        ['c9', 'c1', 'c5', 'c2'],
    ):
        calls = [{'role': 'assistant', 'content': '', 'tool_calls': [
            {'id': cid, 'type': 'function',
             'function': {'name': 'send_file', 'arguments': '{}'}} for cid in ids]}]
        # No tool results at all: interrupted batch.
        fixed = _fix_interleaved_user_messages(calls + [
            {'role': 'user', 'content': 'are you there?'}])
        validate_tool_pairs(fixed)
        assert _tool_ids(fixed) == ids
        assert fixed[-1]['role'] == 'user'


def test_plan_request_repairs_instead_of_reporting_a_size_verdict():
    messages = _reconstruct_llm_messages(_batch_entries())
    # Re-break it the way the old reconstruction did: prose between calls/results.
    broken = [
        messages[0],
        messages[1],                 # assistant(tool_calls=[A,B])
        {'role': 'assistant', 'content': '[File: a.jsonl.gz]'},
        {'role': 'tool', 'tool_call_id': 'call_B', 'content': '{"ok": "sent-B"}'},
        {'role': 'tool', 'tool_call_id': 'call_A', 'content': '{"ok": "sent-A"}'},
    ]
    try:
        validate_tool_pairs(broken)
    except ValueError:
        pass
    else:  # pragma: no cover - guard against a silently-valid fixture
        raise AssertionError('fixture must be invalid before the repair pass')

    plan = plan_request(broken, None, context_window=1_000_000, max_tokens=4096,
                        enforce=True)

    assert plan.fit is True, plan.diagnostic
    assert plan.diagnostic is None
    assert plan.stage == 'tool_protocol_repair'
    validate_tool_pairs(plan.messages)
    assert _tool_ids(plan.messages) == ['call_A', 'call_B']


def test_plan_request_reports_protocol_diagnostic_when_unrepairable():
    """Duplicate call ids cannot be repaired; that must not read as a size issue."""
    broken = [{
        'role': 'assistant', 'content': '',
        'tool_calls': [
            {'id': 'dup', 'type': 'function',
             'function': {'name': 'read_file', 'arguments': '{}'}},
            {'id': 'dup', 'type': 'function',
             'function': {'name': 'read_file', 'arguments': '{}'}},
        ],
    }]
    plan = plan_request(broken, None, context_window=1_000_000, max_tokens=4096,
                        enforce=True)
    assert plan.fit is False
    assert plan.diagnostic in ('invalid_tool_protocol',
                               'invalid_tool_protocol_after_repair')
    # Truthfulness check: it must NOT look like a token-budget overflow.
    assert plan.estimated_tokens < plan.input_budget


def test_send_file_echo_is_deferred_until_batch_end(monkeypatch):
    from backend.agent_runtime import runtime as runtime_mod

    appended = []

    class _FakeLog:
        def append(self, entry):
            appended.append(entry)

    monkeypatch.setattr(runtime_mod.chatlog_manager, 'get',
                        lambda agent_id, session_id: _FakeLog())

    entry = {'type': 'final', 'content': '[File: a.jsonl.gz]'}
    runtime_mod.begin_tool_batch('agent', 'sess')
    runtime_mod.append_or_defer_chatlog_echo('agent', 'sess', entry)
    assert appended == []                     # nothing written mid-batch
    assert runtime_mod.end_tool_batch('agent', 'sess') == 1
    assert appended == [entry]                # flushed after the batch

    # Outside a batch the echo is written immediately.
    runtime_mod.append_or_defer_chatlog_echo('agent', 'sess',
                                             {'type': 'final', 'content': 'x'})
    assert len(appended) == 2
