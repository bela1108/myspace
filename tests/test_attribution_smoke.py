import dnfile.attribution


def test_import():
    assert dnfile.attribution.AttributionStatus.RESOLVED.value == "resolved"
