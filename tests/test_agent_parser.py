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
