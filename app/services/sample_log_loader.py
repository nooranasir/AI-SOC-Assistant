"""Sample log loading utilities.

Purpose:
    Read sample security logs from the repository's top-level logs directory.

Inputs:
    Sample log file names.

Outputs:
    File contents as text.

Dependencies:
    pathlib for filesystem handling and the application settings for paths.
"""

from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class SampleLogLoader:
    """Load sample logs from a fixed directory."""

    sample_logs_directory: Path

    def list_sample_logs(self) -> list[str]:
        """Return the available sample log file names."""
        if not self.sample_logs_directory.exists():
            return []
        return sorted(
            path.name for path in self.sample_logs_directory.iterdir() if path.is_file()
        )

    def load(self, sample_name: str) -> str:
        """Return the contents of a specific sample log file.

        Raises:
            FileNotFoundError: If the requested sample does not exist.
            ValueError: If the requested path escapes the sample directory.
        """
        sample_directory = self.sample_logs_directory.resolve()
        sample_path = (sample_directory / sample_name).resolve()
        if sample_directory not in sample_path.parents and sample_path != sample_directory:
            raise ValueError("Sample log path must stay within the sample directory.")
        return sample_path.read_text(encoding="utf-8")
