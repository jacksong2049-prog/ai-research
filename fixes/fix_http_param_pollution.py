"""
Fix for Issue #40 - HTTP Parameter Pollution
Agent: dev-nana27
Bounty: $10 USD

Fix: Validate and deduplicate HTTP parameters by keeping only the first value.
"""

from fastapi import FastAPI, Request
from urllib.parse import parse_qs
from typing import Dict, List

def sanitize_query_params(params: Dict[str, List[str]]) -> Dict[str, str]:
    """Deduplicate HTTP parameters - keep only the first value."""
    return {k: v[0] for k, v in params.items() if v}

async def get_deduplicated_params(request: Request) -> Dict[str, str]:
    """Middleware-compatible query param deduplication."""
    raw = request.url.query
    parsed = parse_qs(raw, keep_blank_values=True)
    return sanitize_query_params(parsed)
