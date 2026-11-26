name = "minidump"


def __getattr__(attribute):
	# Keep importing ``minidump`` free of the heavier parser modules while still
	# allowing ``from minidump import OfflineDirectoryIndex``.
	if attribute in (
		"OfflineDirectoryIndex",
		"OfflineDirectoryIndexBuilder",
		"DirectoryIndexBuilder",
		"DirectoryIndex",
		"SourceIdentity",
		"SourceId",
		"SealedReceipt",
		"DirectoryCursor",
		"DirectoryEntry",
		"MisappliedCursorError",
		"SourceIdentityMismatchError",
		"DirectoryIndexError",
	):
		from minidump import offline_index
		return getattr(offline_index, attribute)
	raise AttributeError("module %r has no attribute %r" % (__name__, attribute))


__all__ = [
	"OfflineDirectoryIndex",
	"OfflineDirectoryIndexBuilder",
	"DirectoryIndexBuilder",
	"DirectoryIndex",
	"SourceIdentity",
	"SourceId",
	"SealedReceipt",
	"DirectoryCursor",
	"DirectoryEntry",
	"MisappliedCursorError",
	"SourceIdentityMismatchError",
	"DirectoryIndexError",
]
