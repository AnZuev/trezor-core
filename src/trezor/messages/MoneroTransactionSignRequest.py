# Automatically generated by pb2py
# fmt: off
import protobuf as p
from .MoneroTransactionAllOutSetRequest import MoneroTransactionAllOutSetRequest
from .MoneroTransactionFinalRequest import MoneroTransactionFinalRequest
from .MoneroTransactionInitRequest import MoneroTransactionInitRequest
from .MoneroTransactionInputViniRequest import MoneroTransactionInputViniRequest
from .MoneroTransactionInputsPermutationRequest import MoneroTransactionInputsPermutationRequest
from .MoneroTransactionMlsagDoneRequest import MoneroTransactionMlsagDoneRequest
from .MoneroTransactionSetInputRequest import MoneroTransactionSetInputRequest
from .MoneroTransactionSetOutputRequest import MoneroTransactionSetOutputRequest
from .MoneroTransactionSignInputRequest import MoneroTransactionSignInputRequest


class MoneroTransactionSignRequest(p.MessageType):
    FIELDS = {
        1: ('init', MoneroTransactionInitRequest, 0),
        2: ('set_input', MoneroTransactionSetInputRequest, 0),
        3: ('input_permutation', MoneroTransactionInputsPermutationRequest, 0),
        4: ('input_vini', MoneroTransactionInputViniRequest, 0),
        5: ('set_output', MoneroTransactionSetOutputRequest, 0),
        6: ('all_out_set', MoneroTransactionAllOutSetRequest, 0),
        7: ('mlsag_done', MoneroTransactionMlsagDoneRequest, 0),
        8: ('sign_input', MoneroTransactionSignInputRequest, 0),
        9: ('final_msg', MoneroTransactionFinalRequest, 0),
    }

    def __init__(
        self,
        init: MoneroTransactionInitRequest = None,
        set_input: MoneroTransactionSetInputRequest = None,
        input_permutation: MoneroTransactionInputsPermutationRequest = None,
        input_vini: MoneroTransactionInputViniRequest = None,
        set_output: MoneroTransactionSetOutputRequest = None,
        all_out_set: MoneroTransactionAllOutSetRequest = None,
        mlsag_done: MoneroTransactionMlsagDoneRequest = None,
        sign_input: MoneroTransactionSignInputRequest = None,
        final_msg: MoneroTransactionFinalRequest = None,
    ) -> None:
        self.init = init
        self.set_input = set_input
        self.input_permutation = input_permutation
        self.input_vini = input_vini
        self.set_output = set_output
        self.all_out_set = all_out_set
        self.mlsag_done = mlsag_done
        self.sign_input = sign_input
        self.final_msg = final_msg