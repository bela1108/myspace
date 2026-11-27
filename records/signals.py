from django.dispatch import receiver
from django.db.models.signals import post_save, pre_save

from .models import RoutingError, TrackedObject


@receiver(pre_save, sender=TrackedObject)
def validate_tracked_object_routing(sender, instance, raw, using, update_fields, **kwargs):
    expected_db = getattr(instance, "_expected_routing_db", None)
    if expected_db is None:
        raise RoutingError("TrackedObject was sent to pre_save without an explicit using")
    if using != expected_db:
        raise RoutingError(
            f"signal database {using!r} does not match explicit route {expected_db!r}"
        )
    if instance._state.db != using:
        raise RoutingError("instance state database does not match signal database")
    if instance.origin_db != using:
        raise RoutingError("TrackedObject.origin_db must equal the write database")


@receiver(post_save, sender=TrackedObject)
def stamp_signal_route(sender, instance, created, using, **kwargs):
    instance._last_signal_db = using
    instance._last_signal_created = created
