"""spec/channels.json names the two alert channels on buzz.ai-tools.md."""

import json
import uuid
from pathlib import Path

CHANNELS = Path(__file__).resolve().parent.parent / "spec" / "channels.json"


def test_channels_are_distinct_canonical_uuids():
    data = json.loads(CHANNELS.read_text())
    assert set(data) == {"feed", "critical"}
    for value in data.values():
        assert isinstance(value, str)
        assert str(uuid.UUID(value)) == value
    assert data["feed"] != data["critical"]
