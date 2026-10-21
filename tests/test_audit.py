from llmshield.audit import AuditStore


def test_memory_database_persists_across_calls():
    store = AuditStore(":memory:")
    event_id = store.record("request-1", "allow", "mock", [])
    events = store.list_events()
    assert events[0]["id"] == event_id
    assert events[0]["request_id"] == "request-1"
    store.close()


def test_audit_records_only_metadata():
    store = AuditStore(":memory:")
    store.record("request-2", "redact", "mock", [{"category": "pii", "action": "redact"}])
    event = store.list_events()[0]
    assert "prompt" not in event
    assert "response" not in event
    assert "content" not in event
    store.close()
