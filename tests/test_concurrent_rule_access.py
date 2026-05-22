from concurrent.futures import ThreadPoolExecutor

from openclaw_governance_proxy.cache import TTLCache


def test_rule_cache_reload():
    cache = TTLCache(60)
    cache.set([1])
    assert cache.get() == [1]
    cache.invalidate()
    assert cache.get() is None


def test_concurrent_cache_access():
    cache = TTLCache(60)
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(cache.set, range(20)))
    assert cache.get() in range(20)
