"""
Set permutation on the inputs - sorted by key image on host.
"""

from .tsx_sign_builder import TransactionSigningState

from apps.monero.controller import misc
from apps.monero.xmr import common, crypto, monero


async def tsx_inputs_permutation(state: TransactionSigningState, permutation):
    """
    Set permutation on the inputs - sorted by key image on host.
    """
    from trezor.messages.MoneroTransactionInputsPermutationAck import (
        MoneroTransactionInputsPermutationAck
    )

    await state.iface.transaction_step(state.STEP_PERM)

    _tsx_inputs_permutation(state, permutation)
    return MoneroTransactionInputsPermutationAck()


def _tsx_inputs_permutation(self, permutation):
    """
    Set permutation on the inputs - sorted by key image on host.
    """
    self.state.input_permutation()
    self.source_permutation = permutation
    common.check_permutation(permutation)
    self.inp_idx = -1
