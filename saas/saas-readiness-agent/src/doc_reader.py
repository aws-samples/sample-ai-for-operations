# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Document reader for customer-provided documentation.

Reads local files (text, markdown, JSON, PDF, DOCX) and extracts content
for the agent to reason over. The agent uses the extracted text to pre-fill
assessment answers and reduce the number of questions it needs to ask.

PDF and DOCX support require optional dependencies (PyPDF2, python-docx).
If not installed, the tool tells the user which package to install.

Security:
- Reads only from one allowed directory, DOCUMENTS_DIR (default
  ``./documents``). Relative paths resolve against that directory. Every path
  is fully resolved (``..`` segments and symlinks) before the containment
  check, so traversal and symlinks pointing outside the directory are
  rejected. Containment is checked before existence, so the tool does not
  reveal whether files exist elsewhere.
- Never writes, modifies, or transmits file contents externally.
- Not exposed in the AgentCore Runtime profile (see ``build_agent``), where
  callers cannot place files in the container anyway.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

try:
    from src.config import load_documents_dir
except ModuleNotFoundError:  # pragma: no cover - supports direct execution from src/
    from config import load_documents_dir  # type: ignore[import-not-found, no-redef]


# File size limit to avoid blowing up context window (2MB).
MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024

# Supported extensions and their handlers.
TEXT_EXTENSIONS = {".txt", ".md", ".markdown", ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".csv"}
PDF_EXTENSIONS = {".pdf"}
DOCX_EXTENSIONS = {".docx"}
ALL_SUPPORTED = TEXT_EXTENSIONS | PDF_EXTENSIONS | DOCX_EXTENSIONS


def _resolve_base_dir(base_dir: str | os.PathLike[str] | None) -> Path:
    """Resolve the allowed documents directory (DOCUMENTS_DIR by default)."""

    raw = Path(base_dir) if base_dir is not None else Path(load_documents_dir())
    return raw.expanduser().resolve()


def _validate_path(
    file_path: str, base_dir: str | os.PathLike[str] | None = None
) -> tuple[Path | None, str | None]:
    """Validate and resolve a file path. Returns (resolved_path, error_message).

    The path must resolve (after ``..`` and symlinks) to a file inside the
    allowed documents directory.
    """

    base = _resolve_base_dir(base_dir)
    if not base.is_dir():
        return None, (
            f"Documents directory not found: {base}. Create it and copy the "
            "documents you want the agent to read into it (or set DOCUMENTS_DIR)."
        )

    candidate = Path(file_path).expanduser()
    if not candidate.is_absolute():
        candidate = base / candidate
    expanded = candidate.resolve()

    # Containment check comes before any existence check so the tool never
    # confirms whether a file exists outside the allowed directory.
    if expanded != base and base not in expanded.parents:
        return None, (
            f"DENIED: documents must be inside the documents directory ({base}). "
            "Copy the file there and pass its name."
        )

    if not expanded.exists():
        return None, f"File not found: {file_path}"

    if not expanded.is_file():
        return None, f"Not a file: {file_path}"

    if expanded.stat().st_size > MAX_FILE_SIZE_BYTES:
        size_mb = expanded.stat().st_size / (1024 * 1024)
        return None, (
            f"File too large ({size_mb:.1f}MB). Maximum is "
            f"{MAX_FILE_SIZE_BYTES / (1024 * 1024):.0f}MB. "
            "For large documents, consider sharing the most relevant section."
        )

    suffix = expanded.suffix.lower()
    if suffix not in ALL_SUPPORTED:
        return None, (
            f"Unsupported file type: {suffix}. "
            f"Supported: {', '.join(sorted(ALL_SUPPORTED))}"
        )

    return expanded, None


def _read_text(path: Path) -> str:
    """Read a plain text file."""
    return path.read_text(encoding="utf-8", errors="replace")


def _read_pdf(path: Path) -> tuple[str | None, str | None]:
    """Read a PDF file. Returns (text, error)."""
    try:
        from PyPDF2 import PdfReader
    except ImportError:
        return None, (
            "PDF reading requires PyPDF2. Install it with:\n"
            "  pip install PyPDF2\n"
            "Then try again."
        )

    reader = PdfReader(str(path))
    pages = []
    for i, page in enumerate(reader.pages):
        text = page.extract_text()
        if text and text.strip():
            pages.append(f"--- Page {i + 1} ---\n{text.strip()}")

    if not pages:
        return None, "PDF appears to be image-based (no extractable text). Try a text-based document instead."

    return "\n\n".join(pages), None


def _read_docx(path: Path) -> tuple[str | None, str | None]:
    """Read a DOCX file. Returns (text, error)."""
    try:
        from docx import Document
    except ImportError:
        return None, (
            "DOCX reading requires python-docx. Install it with:\n"
            "  pip install python-docx\n"
            "Then try again."
        )

    doc = Document(str(path))
    paragraphs = [p.text for p in doc.paragraphs if p.text.strip()]

    if not paragraphs:
        return None, "DOCX appears to be empty or contains only images/tables."

    return "\n\n".join(paragraphs), None


def read_document(
    file_path: str, base_dir: str | os.PathLike[str] | None = None
) -> dict[str, Any]:
    """Read a document and return its content with metadata.

    Args:
        file_path: File name or path inside the documents directory. Relative
            paths resolve against that directory.
        base_dir: Allowed directory. Defaults to DOCUMENTS_DIR (``./documents``).

    Returns:
        Dict with:
        - success: bool
        - file_name: original filename
        - file_type: extension
        - content: extracted text (if success)
        - char_count: length of extracted content
        - error: error message (if failed)
        - note: guidance for the agent on what to do with the content
    """

    path, error = _validate_path(file_path, base_dir)
    if error or path is None:
        return {"success": False, "file_name": file_path, "error": error}

    suffix = path.suffix.lower()
    file_name = path.name

    # Read based on file type.
    if suffix in TEXT_EXTENSIONS:
        content = _read_text(path)
    elif suffix in PDF_EXTENSIONS:
        content, error = _read_pdf(path)
        if error:
            return {"success": False, "file_name": file_name, "file_type": suffix, "error": error}
    elif suffix in DOCX_EXTENSIONS:
        content, error = _read_docx(path)
        if error:
            return {"success": False, "file_name": file_name, "file_type": suffix, "error": error}
    else:
        return {"success": False, "file_name": file_name, "error": f"No reader for {suffix}"}

    # Truncate if content is extremely long (shouldn't happen with file size
    # limit, but guard against dense text extraction).
    max_chars = 50000
    truncated = False
    if len(content) > max_chars:
        content = content[:max_chars]
        truncated = True

    return {
        "success": True,
        "file_name": file_name,
        "file_type": suffix,
        "content": content,
        "char_count": len(content),
        "truncated": truncated,
        "note": (
            "Read this document and extract any information relevant to the "
            "SaaS readiness assessment dimensions: tenant architecture, identity/"
            "context, onboarding/lifecycle, observability, deployment/automation, "
            "cost/metering, and service model. Use what you find to pre-fill "
            "assessment answers and skip questions the document already answers."
        ),
    }
