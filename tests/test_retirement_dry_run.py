from pycose.retirement import retirement_dry_run


def test_smoke():
    assert retirement_dry_run([], [])["minimum_domain_set"] == []
