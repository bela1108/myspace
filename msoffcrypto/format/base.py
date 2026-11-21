import abc

# For 2 and 3 compatibility
# https://stackoverflow.com/questions/35673474/
ABC = abc.ABCMeta("ABC", (object,), {"__slots__": ()})


class BaseOfficeFile(ABC):
    def __init__(self):
        pass

    def protection_attributes(self):
        """Return the normalized public protection attributes for this file.

        The result is a mapping suitable for
        :func:`msoffcrypto.protection.record_from_attributes`.  Subclasses
        implement this without asking for a password.
        """
        raise NotImplementedError

    def get_protection(self, policy=None):
        """Return a password-free protection record evaluated by *policy*."""
        from msoffcrypto.protection import record_from_attributes

        return record_from_attributes(policy=policy, **self.protection_attributes())

    # Common names used by intake services embedding this library.
    protection_record = get_protection
    get_protection_info = get_protection
    get_encryption_info = get_protection

    def encryption_attributes(self):
        """Alias for :meth:`protection_attributes`."""
        return self.protection_attributes()

    @property
    def protection(self):
        """Protection record using the permissive default policy."""
        return self.get_protection()

    @property
    def protection_info(self):
        """Alias for :attr:`protection`."""
        return self.get_protection()

    @property
    def encryption_info(self):
        """Alias for :attr:`protection` for encryption-oriented callers."""
        return self.get_protection()

    @abc.abstractmethod
    def load_key(self):
        pass

    @abc.abstractmethod
    def decrypt(self, outfile):
        pass

    @abc.abstractmethod
    def is_encrypted(self) -> bool:
        pass
