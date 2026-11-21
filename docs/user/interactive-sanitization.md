# Interactive action review and sanitization

PDF actions are opt-in: reading or cloning a PDF does not change them.  The
interactive sanitizer is a separate explicit step for workflows where a
derived document must not be able to resolve an external resource.

## Audit first

Use `review_interactive_actions()` to inspect every action without changing the
input.  The scanner follows the catalog, the outline tree, page annotations,
the AcroForm field tree, page/catalog additional actions, and the JavaScript
name tree.  Actions are keyed by object identity, so an action shared by a
bookmark, an annotation, and a form widget is one finding with three owners.

```python
from pypdf import PdfReader, review_interactive_actions

review = review_interactive_actions(PdfReader("report.pdf"))
for action in review.actions:
    print(action.key, action.action_type, action.disposition, action.reason)
for bookmark in review.bookmarks:
    print(bookmark.title, bookmark.destination, bookmark.disposition)
```

`approval_scope` records the surfaces, local action types, and named actions
that may be retained.  `unexplained_actions` lists actions whose type or local
destination could not be interpreted.  Unexplained and external actions are
removed by default.

## Write a sanitized derivative

```python
from pypdf import sanitize_interactive_pdf

report = sanitize_interactive_pdf(
    "report.pdf",
    "report-archive.pdf",
)
```

The source path is only opened for reading and is rejected as the output path.
The derived file is re-read and checked before the report is returned.  URI,
remote-go-to, launch, submit/import, JavaScript, media, and unknown actions are
detached.  Approved local `GoTo` actions and named page navigation remain.

The report contains a clear outcome for every action, bookmark, destination,
and form field.  A bookmark whose action was removed remains as an inert title
so its reading order and label are not lost.  The InteractiveSanitizer class
provides the same backend with separate review(), to_bytes(), and sanitize()
calls.

## Approval policy

`SanitizationPolicy` narrows the approval scope:

```python
from pypdf import SanitizationPolicy, sanitize_interactive_pdf

policy = SanitizationPolicy(
    allowed_surfaces={"outline", "annotation"},
    allow_local_navigation=True,
    allowed_named_actions={"/NextPage", "/PrevPage"},
)
report = sanitize_interactive_pdf("report.pdf", "report-archive.pdf", policy=policy)
```

A reviewer callback receives one `ActionFinding` per shared action after the
policy checks have passed.  Returning `False` removes that local action:

```python
report = sanitize_interactive_pdf(
    "report.pdf",
    "report-archive.pdf",
    reviewer=lambda finding: finding.classification == "local_navigation",
)
```

At the writer level, use `writer.sanitize_interactive()` on a cloned,
non-incremental writer.  Incremental writers are rejected because they write
back to the original file.
