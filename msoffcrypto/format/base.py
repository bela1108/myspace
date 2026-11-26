import abc

# For 2 and 3 compatibility
# https://stackoverflow.com/questions/35673474/
ABC = abc.ABCMeta("ABC", (object,), {"__slots__": ()})


class BaseOfficeFile(ABC):
    def __init__(self):
        pass

    @abc.abstractmethod
    def load_key(self):
        pass

    @abc.abstractmethod
    def decrypt(self, outfile):
        pass

    @abc.abstractmethod
    def is_encrypted(self) -> bool:
        pass

    def structure_snapshot(self, **kwargs):
        """Return the local logical/public structure fingerprint."""
        from msoffcrypto.forensic_review import read_structure

        return read_structure(self.file, **kwargs)

    def compare_structure(self, reference=None, **kwargs):
        """Compare this file's local structure with a report/reference."""
        from msoffcrypto.forensic_review import compare_structures

        return compare_structures(self.file, reference, **kwargs)

    compare_local_structure = compare_structure
    local_structure_compare = compare_structure
    verify_evidence_link = compare_structure
