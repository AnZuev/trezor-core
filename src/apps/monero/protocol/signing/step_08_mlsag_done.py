"""
MLSAG message computed.
"""

from .tsx_sign_builder import TransactionSigningState

from apps.monero.controller import misc
from apps.monero.xmr import common, crypto, monero


def tsx_mlsag_ecdh_info(self):
    """
    Sets ecdh info for the incremental hashing mlsag.
    """
    pass


def tsx_mlsag_out_pk(self):
    """
    Sets out_pk for the incremental hashing mlsag.
    """
    if self.num_dests() != len(self.output_pk):
        raise ValueError("Invalid number of ecdh")

    for out in self.output_pk:
        self.full_message_hasher.set_out_pk(out)


async def mlsag_done(self):
    """
    MLSAG message computed.
    """
    from trezor.messages.MoneroTransactionMlsagDoneAck import (
        MoneroTransactionMlsagDoneAck
    )

    self.state.set_final_message_done()
    await self.iface.transaction_step(self.STEP_MLSAG)

    self.tsx_mlsag_ecdh_info()
    self.tsx_mlsag_out_pk()
    self.full_message_hasher.rctsig_base_done()
    self.out_idx = -1
    self.inp_idx = -1

    self.full_message = self.full_message_hasher.get_digest()
    self.full_message_hasher = None

    return MoneroTransactionMlsagDoneAck(full_message_hash=self.full_message)
