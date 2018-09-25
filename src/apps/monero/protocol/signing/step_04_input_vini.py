"""
Set tx.vin[i] for incremental tx prefix hash computation.
After sorting by key images on host.
"""

from .tsx_sign_builder import TransactionSigningState

from apps.monero.controller import misc
from apps.monero.xmr import common, crypto, monero


async def input_vini(state, src_entr, vini_bin, hmac, pseudo_out, pseudo_out_hmac):
    """
    Set tx.vin[i] for incremental tx prefix hash computation.
    After sorting by key images on host.
    Hashes pseudo_out to the final_message.
    """
    from trezor.messages.MoneroTransactionInputViniAck import (
        MoneroTransactionInputViniAck
    )

    await state.iface.transaction_step(
        state.STEP_VINI, state.inp_idx + 1, state.num_inputs()
    )

    if state.inp_idx >= state.num_inputs():
        raise ValueError("Too many inputs")

    state.state.input_vins()
    state.inp_idx += 1

    # HMAC(T_in,i || vin_i)
    hmac_vini = await state.gen_hmac_vini(
        src_entr, vini_bin, state.source_permutation[state.inp_idx]
    )
    if not common.ct_equal(hmac_vini, hmac):
        raise ValueError("HMAC is not correct")

    state.hash_vini_pseudo_out(vini_bin, state.inp_idx, pseudo_out, pseudo_out_hmac)
    return MoneroTransactionInputViniAck()


def hash_vini_pseudo_out(
    state, vini_bin, inp_idx, pseudo_out=None, pseudo_out_hmac=None
):
    """
    Incremental hasing of tx.vin[i] and pseudo output
    """
    state.tx_prefix_hasher.buffer(vini_bin)

    # Pseudo_out incremental hashing - applicable only in simple rct
    if not state.use_simple_rct or state.use_bulletproof:
        return

    idx = state.source_permutation[inp_idx]
    pseudo_out_hmac_comp = crypto.compute_hmac(state.hmac_key_txin_comm(idx), pseudo_out)
    if not common.ct_equal(pseudo_out_hmac, pseudo_out_hmac_comp):
        raise ValueError("HMAC invalid for pseudo outs")

    state.full_message_hasher.set_pseudo_out(pseudo_out)
