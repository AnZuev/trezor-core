"""
All inputs set. Defining rsig parameters.
"""

from .tsx_sign_builder import TransactionSigningState

from apps.monero.controller import misc
from apps.monero.xmr import common, crypto, monero


async def all_in_set(state, rsig_data):
    """
    If in the applicable offloading mode, generate commitment masks.
    """
    state._mem_trace(0)
    state.state.input_all_done()
    await state.iface.transaction_step(state.STEP_ALL_IN)

    from trezor.messages.MoneroTransactionAllInputsSetAck import (
        MoneroTransactionAllInputsSetAck
    )
    from trezor.messages.MoneroTransactionRsigData import MoneroTransactionRsigData

    rsig_data = MoneroTransactionRsigData()
    resp = MoneroTransactionAllInputsSetAck(rsig_data=rsig_data)

    if not state.rsig_offload:
        return resp

    # Simple offloading - generate random masks that sum to the input mask sum.
    tmp_buff = bytearray(32)
    rsig_data.mask = bytearray(32 * state.num_dests())
    state.sumout = crypto.sc_init(0)
    for i in range(state.num_dests()):
        cur_mask = crypto.new_scalar()
        is_last = i + 1 == state.num_dests()
        if is_last and state.use_simple_rct:
            crypto.sc_sub_into(cur_mask, state.sumpouts_alphas, state.sumout)
        else:
            crypto.random_scalar(cur_mask)

        crypto.sc_add_into(state.sumout, state.sumout, cur_mask)
        state.output_masks.append(cur_mask)
        crypto.encodeint_into(tmp_buff, cur_mask)
        utils.memcpy(rsig_data.mask, 32 * i, tmp_buff, 0, 32)

    state.assrt(crypto.sc_eq(state.sumout, state.sumpouts_alphas), "Invalid masks sum")
    state.sumout = crypto.sc_init(0)
    return resp