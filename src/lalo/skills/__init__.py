"""The skill library: dense per-class methodology playbooks the agent recalls and follows.

**This is the primary mechanism**, not fixed detector code — per the
project's own methodology correction (see CLAUDE.md's "Execution model" and
"THE METHODOLOGY CORRECTION" in the governing plan). A vulnerability class
skill packs Attack Surface, Recon signals, Techniques escalating in rigor, a
class-specific L1-L4 proof ladder, and Validation/False-Positive discipline
into one dense playbook the agent recalls by name or topic; the cross-cutting
methodology skills (closure discipline, severity calibration) apply to every
finding regardless of class. Reference reads and what was adopted/rejected
from each are cited per-skill-file; see :mod:`lalo.skills.loader` for the
file-format citation and :mod:`lalo.skills.recall` for the retrieval design.
"""

from .loader import Skill, SkillCategory, SkillLoadError, load_skills
from .recall import RecallResult, recall
from .tool import build_recall_tool

__all__ = [
    "RecallResult",
    "Skill",
    "SkillCategory",
    "SkillLoadError",
    "build_recall_tool",
    "load_skills",
    "recall",
]
