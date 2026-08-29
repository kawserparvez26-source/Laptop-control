import json
import logging
import re
from typing import Dict, Any, Optional

logging.basicConfig(level=logging.INFO, format="[PARSER] %(message)s")
logger = logging.getLogger(__name__)

# Maximum JSON payload size we will attempt to parse
_MAX_PAYLOAD_LENGTH = 5000


class LLMToolParser:
    @staticmethod
    def _extract_fenced_json(text: str) -> Optional[str]:
        """Return the first fenced ```json ... ``` block's JSON content, if any."""
        fenced_re = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)
        m = fenced_re.search(text)
        if m:
            return m.group(1)
        return None

    @staticmethod
    def _extract_first_brace_json(text: str) -> Optional[str]:
        """Scan text for the first balanced JSON object starting at the first '{'.

        This avoids using a fragile regex to match nested braces. We walk the
        string and count brace depth until we find a balanced object. Returns
        the substring including the outer braces, or None if no balanced block
        found or it exceeds the max length.
        """
        start = text.find("{")
        if start == -1:
            return None
        depth = 0
        for i in range(start, len(text)):
            ch = text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[start : i + 1]
                    if len(candidate) > _MAX_PAYLOAD_LENGTH:
                        logger.warning("Extracted JSON payload exceeds max allowed length")
                        return None
                    return candidate
        return None

    @staticmethod
    def parse_ai_response(response_text: str) -> Optional[Dict[str, Any]]:
        """
        Parses the JSON response from the AI model to extract tool instructions.
        Behavior:
          1) Try to extract the first ```json ... ``` fenced block.
          2) If none found, try to extract the first {...} balanced JSON object.
          3) Enforce a maximum extracted length to prevent large payload attacks.
          4) Parse the extracted JSON and return a dict with tool_name and kwargs.
        """
        if not isinstance(response_text, str):
            logger.error("AI response must be a string")
            return None

        cleaned = response_text.strip()

        # 1) Try fenced block first
        payload = LLMToolParser._extract_fenced_json(cleaned)

        # 2) Fallback: find first balanced {...} object in free text
        if payload is None:
            payload = LLMToolParser._extract_first_brace_json(cleaned)

        if payload is None:
            logger.error("No valid JSON block found in AI response")
            return None

        # Enforce payload length limit
        if len(payload) > _MAX_PAYLOAD_LENGTH:
            logger.error("Extracted JSON payload is too large")
            return None

        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            logger.error("Failed to decode extracted JSON payload")
            return None

        tool_name = data.get("tool")
        kwargs = data.get("kwargs", {})

        if not tool_name:
            logger.error("No valid 'tool' name found in AI response payload")
            return None

        if not isinstance(kwargs, dict):
            logger.error("kwargs must be a JSON object/dict")
            return None

        logger.info(f"Successfully parsed command for tool: {tool_name}")
        return {"tool_name": tool_name, "kwargs": kwargs}


if __name__ == "__main__":
    # Test harness
    sample_ai_response = 'Here is the command:\n```json\n{"tool": "ScreenTool", "kwargs": {"quality": "high"}}\n```\nThanks'
    print("Simulating AI output:\n", sample_ai_response)
    parsed = LLMToolParser.parse_ai_response(sample_ai_response)
    print("Extracted Command:", parsed)
