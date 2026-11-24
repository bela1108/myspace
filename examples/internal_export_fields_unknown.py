"""Uninferable: unknown-key updates break the field-set guarantee."""


def export_settings(request):
    settings = {"theme": "dark", "lang": "zh-CN"}
    overrides = request.get("overrides")
    settings.update(overrides)
    for key in request.get("flags", ()):
        settings[key] = True
    return settings
