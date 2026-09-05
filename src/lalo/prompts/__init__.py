"""Per-role system prompts: built-in, schema-validated, operator-overridable."""

from .loader import PROMPTS_DIR, PromptLoadError, load_prompt_template, render_prompt

__all__ = [
    "PROMPTS_DIR",
    "PromptLoadError",
    "load_prompt_template",
    "render_prompt",
]
