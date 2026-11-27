from dataclasses import dataclass

from django.db import router, transaction

from .models import OriginStatus, RoutingError, StatusEvent, TrackedObject


@dataclass(frozen=True)
class HistoricalCandidate:
    object: TrackedObject
    database: str


@dataclass(frozen=True)
class HistoricalReceipt:
    object_id: int
    origin_status: str
    origin_db: str | None
    candidates: tuple[HistoricalCandidate, ...]


@dataclass(frozen=True)
class SignalReceipt:
    signal_db: str
    instance_state_db: str
    origin_db: str
    created: bool


@dataclass(frozen=True)
class WriteReceipt:
    database: str
    object_id: int
    status: str
    origin_status: str
    signal: SignalReceipt
    event_id: int


def _signal_receipt(instance, created):
    signal_db = getattr(instance, "_last_signal_db", None)
    if signal_db is None or signal_db != instance._state.db:
        raise RoutingError("post_save did not provide a verifiable route")
    return SignalReceipt(
        signal_db=signal_db,
        instance_state_db=instance._state.db,
        origin_db=instance.origin_db,
        created=created,
    )


def _router_write_db(model, instance, using):
    routed_db = router.db_for_write(model, instance=instance, using=using)
    if routed_db != using:
        raise RoutingError("router returned a different database than the explicit using")
    return routed_db


def create_tracked_object(*, object_id, name, status, origin_db):
    with transaction.atomic(using=origin_db):
        instance = TrackedObject(
            id=object_id,
            name=name,
            status=status,
            origin_db=origin_db,
            origin_status=OriginStatus.KNOWN,
        )
        instance.save(using=origin_db)
        router_allowed = _router_write_db(TrackedObject, instance, origin_db)
        event = StatusEvent(
            object_id=object_id,
            from_status="",
            to_status=status,
            origin_db=origin_db,
            origin_status=OriginStatus.KNOWN,
            signal_db=instance._last_signal_db,
            router_allowed=router_allowed,
        )
        event.save(using=origin_db)
        return WriteReceipt(
            database=origin_db,
            object_id=object_id,
            status=status,
            origin_status=OriginStatus.KNOWN,
            signal=_signal_receipt(instance, created=True),
            event_id=event.id,
        )


def change_status(*, object_id, to_status, origin_db):
    with transaction.atomic(using=origin_db):
        instance = TrackedObject.objects.using(origin_db).get(
            id=object_id,
            origin_db=origin_db,
        )
        previous_status = instance.status
        instance.status = to_status
        instance.save(using=origin_db, update_fields=["status"])
        router_allowed = _router_write_db(TrackedObject, instance, origin_db)
        event = StatusEvent(
            object_id=object_id,
            from_status=previous_status,
            to_status=to_status,
            origin_db=origin_db,
            origin_status=instance.origin_status,
            signal_db=instance._last_signal_db,
            router_allowed=router_allowed,
        )
        event.save(using=origin_db)
        return WriteReceipt(
            database=origin_db,
            object_id=object_id,
            status=to_status,
            origin_status=instance.origin_status,
            signal=_signal_receipt(instance, created=False),
            event_id=event.id,
        )


def find_tracked_object(*, object_id, search_aliases, origin_db=None):
    candidates = []
    for alias in search_aliases:
        instance = (
            TrackedObject.objects.using(alias)
            .filter(id=object_id)
            .order_by("origin_db")
            .first()
        )
        if instance is not None:
            candidates.append(HistoricalCandidate(object=instance, database=alias))

    if origin_db is not None:
        candidates = tuple(
            candidate
            for candidate in candidates
            if candidate.database == origin_db
            and candidate.object.origin_db == origin_db
        )
        if len(candidates) != 1:
            return HistoricalReceipt(
                object_id=object_id,
                origin_status=OriginStatus.UNRESOLVED,
                origin_db=None,
                candidates=candidates,
            )
        candidate = candidates[0]
        return HistoricalReceipt(
            object_id=object_id,
            origin_status=OriginStatus.KNOWN,
            origin_db=candidate.database,
            candidates=candidates,
        )

    if len(candidates) == 1:
        candidate = candidates[0]
        if candidate.object.origin_db != candidate.database:
            return HistoricalReceipt(
                object_id=object_id,
                origin_status=OriginStatus.UNRESOLVED,
                origin_db=None,
                candidates=tuple(candidates),
            )
        return HistoricalReceipt(
            object_id=object_id,
            origin_status=OriginStatus.KNOWN,
            origin_db=candidate.database,
            candidates=tuple(candidates),
        )

    return HistoricalReceipt(
        object_id=object_id,
        origin_status=OriginStatus.UNRESOLVED,
        origin_db=None,
        candidates=tuple(candidates),
    )
