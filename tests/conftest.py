"""Shared test setup: tests never touch the network unless they patch requests themselves."""
import pytest


@pytest.fixture(autouse=True)
def no_article_fetch(monkeypatch):
    """Full-article reading (threatwatch/article.py) would fetch real pages during scan tests."""
    from threatwatch import article
    monkeypatch.setattr(article, "fetch_body", lambda url, *a, **kw: "")
    article._robots.clear()
