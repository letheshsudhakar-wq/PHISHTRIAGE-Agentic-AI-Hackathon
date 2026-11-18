"""Server-Sent Events (SSE) streaming infrastructure and in-memory store.

Supports real-time trace updates for the Chrome Extension side panel.
"""

import asyncio
import json
from typing import AsyncGenerator
from app.models.schemas import CaseDetails

# In-memory stores
CASE_STORE: dict[str, CaseDetails] = {}
EVENT_QUEUES: dict[str, asyncio.Queue] = {}


def get_event_queue(case_id: str) -> asyncio.Queue:
    """Retrieve or initialize an asyncio Queue for a specific case."""
    if case_id not in EVENT_QUEUES:
        EVENT_QUEUES[case_id] = asyncio.Queue()
    return EVENT_QUEUES[case_id]


async def push_event(case_id: str, event_type: str, payload: dict | None = None) -> None:
    """Push a structured event into the SSE queue for the given case."""
    queue = get_event_queue(case_id)
    event_data = {
        "event": event_type,
        "case_id": case_id,
        "payload": payload or {},
    }
    await queue.put(event_data)


async def sse_event_generator(case_id: str) -> AsyncGenerator[str, None]:
    """Async generator yielding standard SSE formatted lines: 'data: <json>\n\n'.

    Listens until a 'DONE' event is received or generator is closed.
    """
    queue = get_event_queue(case_id)

    try:
        while True:
            # Wait for next event in queue
            event = await queue.get()
            raw_json = json.dumps(event, default=str)
            yield f"data: {raw_json}\n\n"

            # Terminal event closes the stream
            if event.get("event") == "DONE":
                break
    except asyncio.CancelledError:
        # Client disconnected
        pass

