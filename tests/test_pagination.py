from openclaw_governance_proxy.pagination import Page, page_params


def test_pagination():
    assert page_params({"page": "2", "per_page": "100"}) == (2, 100)
    assert page_params({"per_page": "999"}) == (1, 25)
    assert Page([], 1, 25, 26).total_pages == 2
