"""
Sets UTXO one by one.
Computes spending secret key, key image. tx.vin[i] + HMAC, Pedersen commitment on amount.

If number of inputs is small, in-memory mode is used = alpha, pseudo_outs are kept in the Trezor.
Otherwise pseudo_outs are offloaded with HMAC, alpha is offloaded encrypted under AES-GCM() with
key derived for exactly this purpose.
"""

from .tsx_sign_builder import TransactionSigningState

from apps.monero.controller import misc
from apps.monero.xmr import common, crypto, monero


# works with:
# - inp_idx
# - input_count
# - creds,
# - subaddresses,
# - (_mem_trace)
# - key_hmac
# - sumpouts_alphas
# - use_simple_rct
# -
# -


# all works with:
# - ctx (layout)
# - state (to

async def set_input(state: TransactionSigningState, src_entr):
    """
    Sets UTXO one by one.
    Computes spending secret key, key image. tx.vin[i] + HMAC, Pedersen commitment on amount.

    If number of inputs is small, in-memory mode is used = alpha, pseudo_outs are kept in the Trezor.
    Otherwise pseudo_outs are offloaded with HMAC, alpha is offloaded encrypted under Chacha20Poly1305()
    with key derived for exactly this purpose.
    """
    from trezor.messages.MoneroTransactionSetInputAck import (
        MoneroTransactionSetInputAck
    )
    from apps.monero.xmr.enc import chacha_poly
    from apps.monero.xmr.sub import tsx_helper
    from apps.monero.xmr.serialize_messages.tx_prefix import TxinToKey
    from apps.monero.protocol import hmac_encryption_keys

    state.inp_idx += 1

    await state.iface.transaction_step(
        state.STEP_INP, state.inp_idx, state.num_inputs()
    )

    if state.inp_idx >= state.num_inputs():
        raise ValueError("Too many inputs")
    if src_entr.real_output >= len(src_entr.outputs):
        raise ValueError(
            "real_output index %s bigger than output_keys.size() %s"
            % (src_entr.real_output, len(src_entr.outputs))
        )
    state.summary_inputs_money += src_entr.amount

    # Secrets derivation
    out_key = crypto.decodepoint(src_entr.outputs[src_entr.real_output].key.dest)
    tx_key = crypto.decodepoint(src_entr.real_out_tx_key)
    additional_keys = [
        crypto.decodepoint(x) for x in src_entr.real_out_additional_tx_keys
    ]

    secs = monero.generate_tx_spend_and_key_image_and_derivation(
        state.creds,
        state.subaddresses,
        out_key,
        tx_key,
        additional_keys,
        src_entr.real_output_in_tx_index,
    )
    xi, ki, di = secs
    state._mem_trace(1, True)

    # Construct tx.vin
    ki_real = src_entr.multisig_kLRki.ki if state.multi_sig else ki
    vini = TxinToKey(amount=src_entr.amount, k_image=crypto.encodepoint(ki_real))
    vini.key_offsets = tsx_helper.absolute_output_offsets_to_relative(
        [x.idx for x in src_entr.outputs]
    )

    if src_entr.rct:
        vini.amount = 0

    # Serialize with variant code for TxinToKey
    vini_bin = misc.dump_msg(vini, preallocate=64, prefix=b"\x02")
    state._mem_trace(2, True)

    # HMAC(T_in,i || vin_i)
    hmac_vini = await hmac_encryption_keys.gen_hmac_vini(
        state.key_hmac, src_entr, vini_bin, state.inp_idx
    )
    state._mem_trace(3, True)

    # PseudoOuts commitment, alphas stored to state
    pseudo_out = None
    pseudo_out_hmac = None
    alpha_enc = None

    if state.use_simple_rct:
        alpha, pseudo_out = state._gen_commitment(src_entr.amount)
        pseudo_out = crypto.encodepoint(pseudo_out)

        # In full version the alpha is encrypted and passed back for storage
        pseudo_out_hmac = crypto.compute_hmac(
            state.hmac_key_txin_comm(state.inp_idx), pseudo_out
        )
        alpha_enc = chacha_poly.encrypt_pack(
            state.enc_key_txin_alpha(state.inp_idx), crypto.encodeint(alpha)
        )

    spend_enc = chacha_poly.encrypt_pack(
        state.enc_key_spend(state.inp_idx), crypto.encodeint(xi)
    )

    # All inputs done?
    if state.inp_idx + 1 == state.num_inputs():
        tsx_inputs_done()

    return MoneroTransactionSetInputAck(
        vini=vini_bin,
        vini_hmac=hmac_vini,
        pseudo_out=pseudo_out,
        pseudo_out_hmac=pseudo_out_hmac,
        alpha_enc=alpha_enc,
        spend_enc=spend_enc,
    )


def tsx_inputs_done(self):
    """
    All inputs set
    """
    self.state.input_done()
    self.subaddresses = None

    if self.inp_idx + 1 != self.num_inputs():
        raise ValueError("Input count mismatch")


def _gen_commitment(self, in_amount):
    """
    Computes Pedersen commitment - pseudo outs
    Here is slight deviation from the original protocol.
    We want that \\sum Alpha = \\sum A_{i,j} where A_{i,j} is a mask from range proof for output i, bit j.

    Previously this was computed in such a way that Alpha_{last} = \\sum A{i,j} - \\sum_{i=0}^{last-1} Alpha
    But we would prefer to compute commitment before range proofs so alphas are generated completely randomly
    and the last A mask is computed in this special way.
    Returns pseudo_out
    """
    alpha = crypto_check_out_commitment_check_out_commitment.random_scalar()
    self.sumpouts_alphas = crypto.sc_add(self.sumpouts_alphas, alpha)
    return alpha, crypto.gen_commitment(alpha, in_amount)
