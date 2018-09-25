"""
Generates a signature for one input.
"""

import gc

from .tsx_sign_builder import TransactionSigningState

from apps.monero.controller import misc
from apps.monero.xmr import common, crypto, monero


async def sign_input(
    self,
    src_entr,
    vini_bin,
    hmac_vini,
    pseudo_out,
    pseudo_out_hmac,
    alpha_enc,
    spend_enc,
):
    """
    Generates a signature for one input.

    :param src_entr: Source entry
    :param vini_bin: tx.vin[i] for the transaction. Contains key image, offsets, amount (usually zero)
    :param hmac_vini: HMAC for the tx.vin[i] as returned from Trezor
    :param pseudo_out: pedersen commitment for the current input, uses alpha as the mask.
    Only in memory offloaded scenario. Tuple containing HMAC, as returned from the Trezor.
    :param pseudo_out_hmac:
    :param alpha_enc: alpha mask for the current input. Only in memory offloaded scenario,
    tuple as returned from the Trezor
    :param spend_enc:
    :return: Generated signature MGs[i]
    """
    self.state.set_signature()
    await self.iface.transaction_step(
        self.STEP_SIGN, self.inp_idx + 1, self.num_inputs()
    )

    self.inp_idx += 1
    if self.inp_idx >= self.num_inputs():
        raise ValueError("Invalid ins")
    if self.use_simple_rct and alpha_enc is None:
        raise ValueError("Inconsistent1")
    if self.use_simple_rct and pseudo_out is None:
        raise ValueError("Inconsistent2")
    if self.inp_idx >= 1 and not self.use_simple_rct:
        raise ValueError("Inconsistent3")

    inv_idx = self.source_permutation[self.inp_idx]

    # Check HMAC of all inputs
    hmac_vini_comp = await self.gen_hmac_vini(src_entr, vini_bin, inv_idx)
    if not common.ct_equal(hmac_vini_comp, hmac_vini):
        raise ValueError("HMAC is not correct")

    gc.collect()
    self._mem_trace(1)

    if self.use_simple_rct:
        pseudo_out_hmac_comp = crypto.compute_hmac(
            self.hmac_key_txin_comm(inv_idx), pseudo_out
        )
        if not common.ct_equal(pseudo_out_hmac_comp, pseudo_out_hmac):
            raise ValueError("HMAC is not correct")

        gc.collect()
        self._mem_trace(2)

        from apps.monero.xmr.enc import chacha_poly

        alpha_c = crypto.decodeint(
            chacha_poly.decrypt_pack(self.enc_key_txin_alpha(inv_idx), bytes(alpha_enc))
        )
        pseudo_out_c = crypto.decodepoint(pseudo_out)

    elif self.use_simple_rct:
        alpha_c = self.input_alphas[self.inp_idx]
        pseudo_out_c = crypto.decodepoint(self.input_pseudo_outs[self.inp_idx])

    else:
        alpha_c = None
        pseudo_out_c = None

    # Spending secret
    from apps.monero.xmr.enc import chacha_poly

    input_secret = crypto.decodeint(
        chacha_poly.decrypt_pack(self.enc_key_spend(inv_idx), bytes(spend_enc))
    )

    gc.collect()
    self._mem_trace(3)

    # Basic setup, sanity check
    index = src_entr.real_output
    in_sk = misc.StdObj(dest=input_secret, mask=crypto.decodeint(src_entr.mask))
    kLRki = src_entr.multisig_kLRki if self.multi_sig else None

    # Private key correctness test
    self.assrt(
        crypto.point_eq(
            crypto.decodepoint(src_entr.outputs[src_entr.real_output].key.dest),
            crypto.scalarmult_base(in_sk.dest),
        ),
        "a1",
    )
    self.assrt(
        crypto.point_eq(
            crypto.decodepoint(src_entr.outputs[src_entr.real_output].key.mask),
            crypto.gen_commitment(in_sk.mask, src_entr.amount),
        ),
        "a2",
    )

    gc.collect()
    self._mem_trace(4)

    # RCT signature
    gc.collect()
    from apps.monero.xmr import mlsag2

    if self.use_simple_rct:
        # Simple RingCT
        mix_ring = [x.key for x in src_entr.outputs]
        mg, msc = mlsag2.prove_rct_mg_simple(
            self.full_message,
            mix_ring,
            in_sk,
            alpha_c,
            pseudo_out_c,
            kLRki,
            None,
            index,
        )

    else:
        # Full RingCt, only one input
        txn_fee_key = crypto.scalarmult_h(self.get_fee())
        mix_ring = [[x.key] for x in src_entr.outputs]

        mg, msc = mlsag2.prove_rct_mg(
            self.full_message,
            mix_ring,
            [in_sk],
            self.output_sk,
            self.output_pk,
            kLRki,
            None,
            index,
            txn_fee_key,
        )

    gc.collect()
    self._mem_trace(5)

    # Encode
    from apps.monero.xmr.sub.recode import recode_msg

    mgs = recode_msg([mg])
    cout = None

    gc.collect()
    self._mem_trace(6)

    # Multisig values returned encrypted, keys returned after finished successfully.
    if self.multi_sig:
        from apps.monero.xmr.enc import chacha_poly

        cout = chacha_poly.encrypt_pack(self.enc_key_cout(), crypto.encodeint(msc))

    # Final state transition
    if self.inp_idx + 1 == self.num_inputs():
        self.state.set_signature_done()
        await self.iface.transaction_signed()

    gc.collect()
    self._mem_trace()

    from trezor.messages.MoneroTransactionSignInputAck import (
        MoneroTransactionSignInputAck
    )

    return MoneroTransactionSignInputAck(
        signature=misc.dump_msg_gc(mgs[0], preallocate=488, del_msg=True), cout=cout
    )
