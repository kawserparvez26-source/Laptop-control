import sys
import logging
from typing import Dict, Any, Optional
from laptop_control.tools.registry import ToolRegistry
from laptop_control.auth.manager import AuthorizationManager

logging.basicConfig(level=logging.INFO, format="[REAL-AGENT] %(message)s")
logger = logging.getLogger(__name__)

class AgentLoop:
    def __init__(self, registry: ToolRegistry, require_human_approval: bool = True):
        self.registry = registry
        self.require_human_approval = require_human_approval

    def request_approval(self, tool_name: str, kwargs: Dict[str, Any]) -> bool:
        """Real interactive operator confirmation prompt in Kali Linux terminal."""
        if not self.require_human_approval:
            return True
            
        print("\n" + "="*50)
        print("[CRITICAL SECURITY ALERT] AI Agent requests action on your system!")
        print(f"Target Tool : {tool_name}")
        print(f"Parameters  : {kwargs}")
        print("="*50)
        
        while True:
            choice = input("Authorize and execute this tool? (y/n): ").strip().lower()
            if choice == 'y':
                logger.info(f"Operator APPROVED execution of {tool_name}.")
                return True
            elif choice == 'n':
                logger.warning(f"Operator REJECTED execution of {tool_name}.")
                return False
            else:
                print("Invalid input. Please type 'y' (yes) or 'n' (no).")

    def execute_ai_action(self, tool_name: str, **kwargs) -> Any:
        """Executes the tool via the real ToolRegistry after human authorization."""
        print(f"\n[AGENT] Evaluating requested tool: {tool_name}")
        
        # 1. Ask human operator for real permission
        if not self.request_approval(tool_name, kwargs):
            logger.info("Action aborted by operator policy.")
            return {"status": "aborted", "reason": "operator_rejected"}

        # 2. Execute the tool using the real ToolRegistry (which handles auth, audit, and emergency stop)
        try:
            logger.info(f"Dispatching {tool_name} to real ToolRegistry...")
            result = self.registry.execute(tool_name, **kwargs)
            logger.info(f"Tool {tool_name} executed successfully.")
            return {"status": "success", "result": result}
        except Exception as e:
            logger.error(f"Failed to execute tool {tool_name}: {e}")
            return {"status": "error", "message": str(e)}
