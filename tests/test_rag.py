import pytest
from app.rag import RAGEngine, get_rag_engine


def test_rag_engine_loading():
    engine = get_rag_engine()
    assert len(engine.documents) >= 4
    filenames = [doc.filename for doc in engine.documents]
    assert "powershell_playbook.txt" in filenames
    assert "incident_response.txt" in filenames
    assert "suspicious_login.txt" in filenames
    assert "endpoint_investigation.txt" in filenames


def test_rag_search_powershell():
    engine = get_rag_engine()
    results = engine.search("powershell encodedcommand bypass downloadstring", top_k=2)
    assert len(results) > 0
    top_result = results[0]
    assert "PowerShell" in top_result["title"]
    assert top_result["score"] > 0.1
    assert "content_snippet" in top_result


def test_rag_search_login():
    engine = get_rag_engine()
    results = engine.search("impossible travel brute force failed logon 4625 MFA", top_k=2)
    assert len(results) > 0
    top_result = results[0]
    assert "Login" in top_result["title"] or "Credential" in top_result["title"]
    assert top_result["score"] > 0.1


def test_rag_empty_query():
    engine = get_rag_engine()
    results = engine.search("", top_k=2)
    # Even on empty, shouldn't crash
    assert isinstance(results, list)
