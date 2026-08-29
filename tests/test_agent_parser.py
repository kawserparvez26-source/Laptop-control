import pytest
from laptop_control.agent.parser import LLMToolParser

def test_parser_valid_json():
    response = '{"tool": "ScreenTool", "kwargs": {"resolution": "1920x1080"}}'
    parsed = LLMToolParser.parse_ai_response(response)
    assert parsed is not None
    assert parsed["tool_name"] == "ScreenTool"
    assert parsed["kwargs"] == {"resolution": "1920x1080"}

def test_parser_fenced_json():
    response = '```json\n{"tool": "ListDirTool", "kwargs": {"path": "/tmp"}}\n```'
    parsed = LLMToolParser.parse_ai_response(response)
    assert parsed is not None
    assert parsed["tool_name"] == "ListDirTool"

def test_parser_invalid_json():
    response = 'This is not json at all'
    assert LLMToolParser.parse_ai_response(response) is None

def test_parser_missing_tool_field():
    response = '{"kwargs": {"resolution": "1920x1080"}}'
    assert LLMToolParser.parse_ai_response(response) is None

# Negative/edge cases

def test_parser_fenced_json_with_extra_text():
    # AI sometimes adds conversational text before or after the JSON block
    response = "Sure, I can help with that.\n```json\n{\"tool\": \"ScreenTool\", \"kwargs\": {}}\n```\nHope this helps!"
    # The updated parser extracts the fenced JSON block even when surrounded by text
    parsed = LLMToolParser.parse_ai_response(response)
    assert parsed is not None
    assert parsed["tool_name"] == "ScreenTool"


def test_parser_rejects_binary_or_huge_payloads():
    huge_string = "A" * 10000
    response = f'{{"tool": "ScreenTool", "kwargs": {{"data": "{huge_string}"}}}}'
    parsed = LLMToolParser.parse_ai_response(response)
    # Parser will now reject overly large extracted payloads (exceeds 5000 char limit)
    assert parsed is None
