from urllib.parse import unquote

from django import urls as urlresolvers
from django.conf import settings
from django.contrib import admin
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest
from django.template.response import TemplateResponse
from django.urls import path, reverse
from django.urls.exceptions import NoReverseMatch
from django.utils.encoding import smart_str
from django.utils.html import format_html
from django.utils.text import capfirst
from django.utils.timezone import is_aware, localtime
from django.utils.translation import gettext_lazy as _

from auditlog import get_logentry_model
from auditlog.pagination import AuditLogCursorPaginator, AuditLogScope
from auditlog.render import get_field_verbose_name, render_logentry_changes_html
from auditlog.signals import accessed

LogEntry = get_logentry_model()

MAX = 75


class LogEntryAdminMixin:
    request: HttpRequest
    CID_TITLE = _("Click to filter by records with this correlation id")

    @admin.display(description=_("Created"))
    def created(self, obj):
        if is_aware(obj.timestamp):
            return localtime(obj.timestamp)
        return obj.timestamp

    @admin.display(description=_("User"))
    def user_url(self, obj):
        if obj.actor:
            app_label, model = settings.AUTH_USER_MODEL.split(".")
            viewname = f"admin:{app_label}_{model.lower()}_change"
            try:
                link = urlresolvers.reverse(viewname, args=[obj.actor.pk])
            except NoReverseMatch:
                return "%s" % (obj.actor)
            return format_html('<a href="{}">{}</a>', link, obj.actor)

        return "system"

    @admin.display(description=_("Resource"))
    def resource_url(self, obj):
        app_label, model = obj.content_type.app_label, obj.content_type.model
        viewname = f"admin:{app_label}_{model}_change"
        try:
            args = [obj.object_pk] if obj.object_id is None else [obj.object_id]
            link = urlresolvers.reverse(viewname, args=args)
        except NoReverseMatch:
            return obj.object_repr
        else:
            return format_html(
                '<a href="{}">{} - {}</a>', link, obj.content_type, obj.object_repr
            )

    @admin.display(description=_("Changes"))
    def msg_short(self, obj):
        if obj.action in [LogEntry.Action.DELETE, LogEntry.Action.ACCESS]:
            return ""  # delete
        changes = obj.changes_dict
        s = "" if len(changes) == 1 else "s"
        fields = ", ".join(changes.keys())
        if len(fields) > MAX:
            i = fields.rfind(" ", 0, MAX)
            fields = fields[:i] + " .."
        return "%d change%s: %s" % (len(changes), s, fields)

    @admin.display(description=_("Changes"))
    def msg(self, obj):
        return render_logentry_changes_html(obj)

    @admin.display(description="Correlation ID")
    def cid_url(self, obj):
        cid = obj.cid
        if cid:
            url = self._add_query_parameter("cid", cid)
            return format_html(
                '<a href="{}" title="{}">{}</a>', url, self.CID_TITLE, cid
            )

    def _add_query_parameter(self, key: str, value: str):
        full_path = self.request.get_full_path()
        delimiter = "&" if "?" in full_path else "?"

        return f"{full_path}{delimiter}{key}={value}"

    def field_verbose_name(self, obj, field_name: str):
        """
        Use `auditlog.render.get_field_verbose_name` instead.
        This method is kept for backward compatibility.
        """
        return get_field_verbose_name(obj, field_name)


class LogAccessMixin:
    def render_to_response(self, context, **response_kwargs):
        obj = self.get_object()
        accessed.send(obj.__class__, instance=obj)
        return super().render_to_response(context, **response_kwargs)


class AuditlogHistoryAdminMixin:
    """
    Add an audit log history view to a model admin.
    """

    auditlog_history_template = "auditlog/object_history.html"
    show_auditlog_history_link = False
    auditlog_history_per_page = 10
    auditlog_cursor_param = "cursor"

    def get_list_display(self, request):
        list_display = list(super().get_list_display(request))
        if self.show_auditlog_history_link and "auditlog_link" not in list_display:
            list_display.append("auditlog_link")

        return list_display

    def get_urls(self):
        opts = self.model._meta
        info = opts.app_label, opts.model_name
        my_urls = [
            path(
                "<path:object_id>/auditlog/",
                self.admin_site.admin_view(self.auditlog_history_view),
                name="%s_%s_auditlog" % info,
            )
        ]

        return my_urls + super().get_urls()

    def auditlog_history_view(self, request, object_id, extra_context=None):
        obj = self.get_object(request, unquote(object_id))
        if not self.has_view_permission(request, obj):
            raise PermissionDenied

        log_entry_queryset = LogEntry.objects.get_for_object(obj).select_related(
            "actor"
        )
        scope = self.get_auditlog_scope(request, obj)

        paginator = AuditLogCursorPaginator(
            log_entry_queryset, self.auditlog_history_per_page, scope
        )
        page_obj = paginator.get_page(request.GET.get(self.auditlog_cursor_param))

        context = {
            **self.admin_site.each_context(request),
            "title": _("Audit log: %s") % obj,
            "module_name": str(capfirst(self.model._meta.verbose_name_plural)),
            "page_var": self.auditlog_cursor_param,
            "pagination_required": page_obj.has_next or page_obj.has_previous,
            "next_cursor": page_obj.next_cursor,
            "previous_cursor": page_obj.previous_cursor,
            "object": obj,
            "opts": self.model._meta,
            "log_entries": page_obj,
            **(extra_context or {}),
        }

        return TemplateResponse(request, self.auditlog_history_template, context)

    def get_auditlog_scope(self, request, obj):
        return AuditLogScope(
            key=self.get_auditlog_scope_key(request, obj),
            revision=self.get_auditlog_scope_revision(request, obj),
            queryset_filter=self.get_auditlog_scope_filter(request, obj),
        )

    def get_auditlog_scope_key(self, request, obj):
        opts = self.model._meta
        return f"{opts.app_label}.{opts.model_name}:{obj.pk}"

    def get_auditlog_scope_revision(self, request, obj):
        return None

    def get_auditlog_scope_filter(self, request, obj):
        content_type = ContentType.objects.get_for_model(obj.__class__)
        pk = obj._meta.pk.value_from_object(obj)
        if isinstance(pk, int):
            return {"content_type": content_type, "object_id": pk}
        return {"content_type": content_type, "object_pk": smart_str(pk)}

    @admin.display(description=_("Audit log"))
    def auditlog_link(self, obj):
        opts = self.model._meta
        url = reverse(
            f"admin:{opts.app_label}_{opts.model_name}_auditlog",
            args=[obj.pk],
        )

        return format_html('<a href="{}">{}</a>', url, _("View"))
