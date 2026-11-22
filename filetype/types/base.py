# -*- coding: utf-8 -*-


class Type(object):
    """
    Represents the file type object inherited by
    specific file type matchers.
    Provides convenient accessor and helper methods.
    """
    # Matcher lifecycle metadata. Handlers can override these class
    # attributes or pass explicit values to ``__init__``.
    VERSION = 1
    HANDLER = None
    STATUS = 'active'
    READ_ONLY = False
    AVAILABLE = True

    def __init__(self, mime, extension, version=None, handler=None,
                 status=None, read_only=None, available=None):
        self.__mime = mime
        self.__extension = extension
        self.__version = version
        self.__handler = handler
        self.__status = status
        self.__read_only = read_only
        self.__available = available

    @property
    def mime(self):
        return self.__mime

    @property
    def extension(self):
        return self.__extension

    @property
    def version(self):
        if self.__version is not None:
            return self.__version
        return self.VERSION

    @property
    def handler(self):
        return self.__handler or self.HANDLER or type(self).__name__

    @property
    def handler_id(self):
        return '{0}@{1}'.format(self.handler, self.version)

    @property
    def status(self):
        if self.__status is not None:
            return self.__status
        if not self.available:
            return 'retired'
        return self.STATUS or 'active'

    @property
    def read_only(self):
        if self.__read_only is not None:
            return self.__read_only
        return self.READ_ONLY

    @property
    def available(self):
        if self.__available is not None:
            return self.__available
        return self.AVAILABLE

    def is_extension(self, extension):
        return self.__extension is extension

    def is_mime(self, mime):
        return self.__mime is mime

    def match(self, buf):
        raise NotImplementedError
