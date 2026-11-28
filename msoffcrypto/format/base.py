import abc

# For 2 and 3 compatibility
# https://stackoverflow.com/questions/35673474/
ABC = abc.ABCMeta("ABC", (object,), {"__slots__": ()})


class BaseOfficeFile(ABC):
    def __init__(self):
        pass

    def close(self):
        """Release resources owned by this file object."""
        input_contract = getattr(self, "input_contract", None)
        if input_contract is not None:
            input_contract.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
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
