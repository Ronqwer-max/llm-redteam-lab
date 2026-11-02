"""Attack modules. Importing this package registers every attack."""

from .agent_escalation import PrivilegeEscalationAttack
from .base import Attack, RunContext, merge_findings
from .direct_injection import DirectInjectionAttack
from .jailbreak import JailbreakSearchAttack
from .memory_extraction import MemoryExtractionAttack
from .multimodal import MultimodalInjectionAttack

__all__ = [
    "Attack",
    "RunContext",
    "merge_findings",
    "DirectInjectionAttack",
    "JailbreakSearchAttack",
    "PrivilegeEscalationAttack",
    "MemoryExtractionAttack",
    "MultimodalInjectionAttack",
]
