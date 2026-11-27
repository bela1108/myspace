from django.db import models


class RoutingError(RuntimeError):
    pass


class OriginStatus(models.TextChoices):
    KNOWN = "known", "known"
    UNRESOLVED = "unresolved", "unresolved"


class LifecycleStatus(models.TextChoices):
    PENDING = "pending", "pending"
    ACTIVE = "active", "active"
    ARCHIVED = "archived", "archived"


class RoutedModel(models.Model):
    class Meta:
        abstract = True

    def save(self, *args, using=None, **kwargs):
        if using is None:
            raise RoutingError(
                f"{self.__class__.__name__}.save() requires an explicit using= alias"
            )
        self._expected_routing_db = using
        self._state.db = using
        super().save(*args, using=using, **kwargs)
        self._state.db = using


class RoutedQuerySet(models.QuerySet):
    def _require_explicit_database(self):
        if not self._db:
            raise RoutingError(
                f"{self.model.__name__} queryset requires .using('<alias>')"
            )

    def create(self, **kwargs):
        self._require_explicit_database()
        return super().create(**kwargs)

    def bulk_create(self, objs, *args, **kwargs):
        self._require_explicit_database()
        for instance in objs:
            instance._state.db = self.db
            instance._expected_routing_db = self.db
        return super().bulk_create(objs, *args, **kwargs)

    def update(self, **kwargs):
        self._require_explicit_database()
        return super().update(**kwargs)

    def delete(self):
        self._require_explicit_database()
        return super().delete()


class RoutedManager(models.Manager.from_queryset(RoutedQuerySet)):
    pass


class TrackedObject(RoutedModel):
    objects = RoutedManager()

    id = models.PositiveBigIntegerField(primary_key=True)
    name = models.CharField(max_length=120)
    status = models.CharField(
        max_length=20,
        choices=LifecycleStatus.choices,
        default=LifecycleStatus.PENDING,
    )
    origin_db = models.CharField(max_length=64)
    origin_status = models.CharField(
        max_length=20,
        choices=OriginStatus.choices,
        default=OriginStatus.KNOWN,
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["id", "origin_db"],
                name="unique_object_origin",
            )
        ]

    def save(self, *args, using=None, **kwargs):
        if not self.origin_db:
            raise RoutingError("TrackedObject.origin_db cannot be empty")
        super().save(*args, using=using, **kwargs)


class StatusEvent(RoutedModel):
    objects = RoutedManager()

    object_id = models.PositiveBigIntegerField()
    from_status = models.CharField(max_length=20, choices=LifecycleStatus.choices)
    to_status = models.CharField(max_length=20, choices=LifecycleStatus.choices)
    origin_db = models.CharField(max_length=64)
    origin_status = models.CharField(max_length=20, choices=OriginStatus.choices)
    signal_db = models.CharField(max_length=64, blank=True)
    router_allowed = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=["object_id", "origin_db"])]
