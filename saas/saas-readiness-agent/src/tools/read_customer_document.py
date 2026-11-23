# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Data retrieval tool: read a customer document from DOCUMENTS_DIR."""

from __future__ import annotations

from typing import Any

from strands import tool

from src.doc_reader import read_document


@tool
def read_customer_document(file_path: str) -> dict[str, Any]:
    """Read a customer-provided document to extract assessment-relevant information.

    Reads only from the documents directory (DOCUMENTS_DIR, default
    ./documents). Ask the customer to copy files there, then pass the file
    name. Paths outside that directory are refused. Use this when the customer
    offers documentation (architecture docs, runbooks, wikis, design docs) so
    you can pre-fill assessment answers and reduce the number of questions.

    Args:
        file_path: File name (or relative path) inside the documents
            directory. Supports: .txt, .md, .json, .yaml, .yml, .toml, .cfg,
            .ini, .csv, .pdf (requires PyPDF2), .docx (requires python-docx)

    Returns:
        Dict with file content and metadata. On success, read the content
        and extract signals relevant to the 7 assessment dimensions. Use
        extracted information to pre-fill answers and skip questions the
        document already covers.
    """

    return read_document(file_path)
