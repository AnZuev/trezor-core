# Automatically generated by pb2py
# fmt: off
import protobuf as p
if __debug__:
    try:
        from typing import List
    except ImportError:
        List = None  # type: ignore


class MoneroSubAddrIndicesList(p.MessageType):
    FIELDS = {
        1: ('account', p.UVarintType, 0),
        2: ('minor_indices', p.UVarintType, p.FLAG_REPEATED),
    }

    def __init__(
        self,
        account: int = None,
        minor_indices: List[int] = None,
    ) -> None:
        self.account = account
        self.minor_indices = minor_indices if minor_indices is not None else []