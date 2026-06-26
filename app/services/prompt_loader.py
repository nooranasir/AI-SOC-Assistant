"""Utilities for loading editable prompt files from disk.

Purpose:
    Keep LLM prompts outside Python code so they can be reviewed and updated
    without changing the application logic.

Inputs:
    A prompt name relative to the configured prompts directory.

Outputs:
    The prompt content as a string.

Dependencies:
    pathlib for filesystem handling.
"""

from pathlib import Path


class PromptLoader:
    """Load prompt files from a configured directory."""

    def __init__(self, prompt_directory: Path) -> None:
        """Initialize the loader with the base prompt directory."""
        self._prompt_directory = prompt_directory

    def load(self, prompt_name: str) -> str:
        """Return the contents of a prompt file.

        Args:
            prompt_name: File name of the prompt within the prompt directory.

        Raises:
            FileNotFoundError: If the prompt file does not exist.
        """
        prompt_path = self._prompt_directory / prompt_name
        return prompt_path.read_text(encoding="utf-8")