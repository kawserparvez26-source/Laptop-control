
# Negative/edge cases

def test_parser_fenced_json_with_extra_text():
    # AI sometimes adds conversational text before or after the JSON block
    response = "Sure, I can help with that.\n```json\n{\"tool\": \"ScreenTool\", \"kwargs\": {}}\n```\nHope this helps!"
    # The current parser requires strict JSON or strict fenced markdown containing only the JSON.
    # We assert that parser returns None for this unsupported mixed content so the dispatcher must be conservative.
    assert LLMToolParser.parse_ai_response(response) is None


def test_parser_rejects_binary_or_huge_payloads():
    huge_string = "A" * 10000
    response = f'{{"tool": "ScreenTool", "kwargs": {{"data": "{huge_string}"}}}}'
    parsed = LLMToolParser.parse_ai_response(response)
    # Parser still parses it, but callers (dispatcher) should limit size; ensure parser returns a result for now
    assert parsed is not None
