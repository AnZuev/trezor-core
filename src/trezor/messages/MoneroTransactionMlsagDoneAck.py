# Automatically generated by pb2py
# fmt: off
import protobuf as p


class MoneroTransactionMlsagDoneAck(p.MessageType):
    FIELDS = {
        1: ('full_message_hash', p.BytesType, 0),
    }

    def __init__(
        self,
        full_message_hash: bytes = None,
    ) -> None:
        self.full_message_hash = full_message_hash