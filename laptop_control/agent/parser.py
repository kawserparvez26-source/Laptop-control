import json
import logging
from typing import Dict, Any, Optional

logging.basicConfig(level=logging.INFO, format="[PARSER] %(message)s")
logger = logging.getLogger(__name__)

class LLMToolParser:
    @staticmethod
    def parse_ai_response(response_text: str) -> Optional[Dict[str, Any]]:
        """
        Parses the JSON response from the AI model to extract tool instructions.
        Expected format: {"tool": "ToolName", "kwargs": {"param1": "value1"}}
        """
        try:
            # Strip any markdown formatting (like ```json ... ```) if the AI includes it
            cleaned_text = response_text.strip()
            if cleaned_text.startswith("```json"):
                cleaned_text = cleaned_text[7:]
            if cleaned_text.endswith("```"):
                cleaned_text = cleaned_text[:-3]
                
            data = json.loads(cleaned_text.strip())
            tool_name = data.get("tool")
            kwargs = data.get("kwargs", {})
            
            if not tool_name:
                logger.error("No valid 'tool' name found in AI response.")
                return None
                
            logger.info(f"Successfully parsed command for tool: {tool_name}")
            return {"tool_name": tool_name, "kwargs": kwargs}
            
        except json.JSONDecodeError:
            logger.error("Failed to parse AI response. Ensure output is valid JSON.")
            return None

if __name__ == "__main__":
    # Test the parser with a dummy AI response
    sample_ai_response = '{"tool": "ScreenTool", "kwargs": {"quality": "high"}}'
    print(f"Simulating AI output: {sample_ai_response}")
    parsed = LLMToolParser.parse_ai_response(sample_ai_response)
    print(f"Extracted Command: {parsed}")
