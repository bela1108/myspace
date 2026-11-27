from django.db import models


class ExplicitOriginRouter:
    app_labels = {"records"}
    allowed_aliases = {"default", "archive", "business", "compliance"}

    def _is_routed_model(self, model):
        return model._meta.app_label in self.app_labels

    def db_for_read(self, model, **hints):
        if not self._is_routed_model(model):
            return None
        instance = hints.get("instance")
        origin_db = hints.get("origin_db")
        candidate = origin_db or getattr(instance, "origin_db", None)
        if candidate not in self.allowed_aliases:
            raise RuntimeError("records reads require an explicit origin_db hint")
        return candidate

    def db_for_write(self, model, **hints):
        if not self._is_routed_model(model):
            return None
        instance = hints.get("instance")
        state = getattr(instance, "_state", None)
        using = hints.get("using") or getattr(state, "db", None)
        expected = getattr(instance, "_expected_routing_db", None) or using
        if expected not in self.allowed_aliases:
            raise RuntimeError("records writes require an explicit database alias")
        if using and expected and using != expected:
            raise RuntimeError("database routing hint does not match the explicit using")
        return expected

    def allow_relation(self, obj1, obj2, **hints):
        if self._is_routed_model(obj1) or self._is_routed_model(obj2):
            return obj1._state.db == obj2._state.db
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        if app_label in self.app_labels:
            return db in self.allowed_aliases
        return None
