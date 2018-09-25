"""
Set destination entry one by one.
Computes destination stealth address, amount key, range proof + HMAC, out_pk, ecdh_info.
"""
import gc

from .tsx_sign_builder import TransactionSigningState

from apps.monero.controller import misc
from apps.monero.xmr import common, crypto, monero


async def set_out1(self, dst_entr, dst_entr_hmac, rsig_data=None):
    """
    Set destination entry one by one.
    Computes destination stealth address, amount key, range proof + HMAC, out_pk, ecdh_info.
    """
    self._mem_trace(0, True)
    mods = utils.unimport_begin()

    await self.iface.transaction_step(self.STEP_OUT, self.out_idx + 1, self.num_dests())
    self._mem_trace(1)

    if self.state.is_input_vins() and self.inp_idx + 1 != self.num_inputs():
        raise ValueError("Invalid number of inputs")

    self.state.set_output()
    self.out_idx += 1
    self._mem_trace(2, True)

    if dst_entr.amount <= 0 and self.tx.version <= 1:
        raise ValueError("Destination with wrong amount: %s" % dst_entr.amount)

    # HMAC check of the destination
    dst_entr_hmac_computed = await self.gen_hmac_tsxdest(dst_entr, self.out_idx)
    if not common.ct_equal(dst_entr_hmac, dst_entr_hmac_computed):
        raise ValueError("HMAC invalid")
    del (dst_entr_hmac, dst_entr_hmac_computed)
    self._mem_trace(3, True)

    # First output - tx prefix hasher - size of the container
    if self.out_idx == 0:
        self.tx_prefix_hasher.container_size(self.num_dests())
    self._mem_trace(4, True)

    self.summary_outs_money += dst_entr.amount
    utils.unimport_end(mods)
    self._mem_trace(5, True)

    # Range proof first, memory intensive
    rsig, mask = self._range_proof(self.out_idx, dst_entr.amount, rsig_data)
    utils.unimport_end(mods)
    self._mem_trace(6, True)

    # Amount key, tx out key
    additional_txkey_priv = self._set_out1_additional_keys(dst_entr)
    derivation = self._set_out1_derivation(dst_entr, additional_txkey_priv)
    amount_key = crypto.derivation_to_scalar(derivation, self.out_idx)
    tx_out_key = crypto.derive_public_key(
        derivation, self.out_idx, crypto.decodepoint(dst_entr.addr.spend_public_key)
    )
    del (derivation, additional_txkey_priv)
    self._mem_trace(7, True)

    # Tx header prefix hashing, hmac dst_entr
    tx_out_bin, hmac_vouti = await self._set_out1_tx_out(dst_entr, tx_out_key)
    self._mem_trace(11, True)

    # Out_pk, ecdh_info
    out_pk, ecdh_info_bin = self._set_out1_ecdh(
        dest_pub_key=tx_out_key,
        amount=dst_entr.amount,
        mask=mask,
        amount_key=amount_key,
    )
    del (dst_entr, mask, amount_key, tx_out_key)
    self._mem_trace(12, True)

    # Incremental hashing of the ECDH info.
    # RctSigBase allows to hash only one of the (ecdh, out_pk) as they are serialized
    # as whole vectors. Hashing ECDH info saves state space.
    self.full_message_hasher.set_ecdh(ecdh_info_bin)
    self._mem_trace(13, True)

    # Output_pk is stored to the state as it is used during the signature and hashed to the
    # RctSigBase later.
    self.output_pk.append(out_pk)
    self._mem_trace(14, True)

    from trezor.messages.MoneroTransactionSetOutputAck import (
        MoneroTransactionSetOutputAck
    )

    out_pk_bin = bytearray(64)
    utils.memcpy(out_pk_bin, 0, out_pk.dest, 0, 32)
    utils.memcpy(out_pk_bin, 32, out_pk.mask, 0, 32)

    return MoneroTransactionSetOutputAck(
        tx_out=tx_out_bin,
        vouti_hmac=hmac_vouti,
        rsig_data=self._return_rsig_data(rsig),
        out_pk=out_pk_bin,
        ecdh_info=ecdh_info_bin,
    )


async def _set_out1_tx_out(self, dst_entr, tx_out_key):
    # Manual serialization of TxOut(0, TxoutToKey(key))
    tx_out_bin = bytearray(34)
    tx_out_bin[0] = 0  # amount varint
    tx_out_bin[1] = 2  # variant code TxoutToKey
    crypto.encodepoint_into(tx_out_bin, tx_out_key, 2)
    self._mem_trace(8)

    # Tx header prefix hashing
    self.tx_prefix_hasher.buffer(tx_out_bin)
    self._mem_trace(9, True)

    # Hmac dest_entr.
    hmac_vouti = await self.gen_hmac_vouti(dst_entr, tx_out_bin, self.out_idx)
    self._mem_trace(10, True)
    return tx_out_bin, hmac_vouti


def _range_proof(self, idx, amount, rsig_data=None):
    """
    Computes rangeproof and related information - out_sk, out_pk, ecdh_info.
    In order to optimize incremental transaction build, the mask computation is changed compared
    to the official Monero code. In the official code, the input pedersen commitments are computed
    after range proof in such a way summed masks for commitments (alpha) and rangeproofs (ai) are equal.

    In order to save roundtrips we compute commitments randomly and then for the last rangeproof
    a[63] = (\\sum_{i=0}^{num_inp}alpha_i - \\sum_{i=0}^{num_outs-1} amasks_i) - \\sum_{i=0}^{62}a_i

    The range proof is incrementally hashed to the final_message.
    """
    from apps.monero.xmr import ring_ct

    mask = self._get_out_mask(idx)
    self.output_amounts.append(amount)
    provided_rsig = (
        rsig_data.rsig
        if rsig_data and rsig_data.rsig and len(rsig_data.rsig) > 0
        else None
    )
    if not self.rsig_offload and provided_rsig:
        raise misc.TrezorError("Provided unexpected rsig")
    if not self.rsig_offload:
        self.output_masks.append(mask)

    # Batching
    bidx = self._get_rsig_batch(idx)
    batch_size = self.rsig_grp[bidx]
    last_in_batch = self._is_last_in_batch(idx, bidx)
    if self.rsig_offload and provided_rsig and not last_in_batch:
        raise misc.TrezorError("Provided rsig too early")
    if self.rsig_offload and last_in_batch and not provided_rsig:
        raise misc.TrezorError("Rsig expected, not provided")

    # Batch not finished, skip range sig generation now
    if not last_in_batch:
        return None, mask

    # Rangeproof
    # Pedersen commitment on the value, mask from the commitment, range signature.
    C, rsig = None, None

    self._mem_trace("pre-rproof" if __debug__ else None, collect=True)
    if not self.rsig_offload and self.use_bulletproof:
        rsig = ring_ct.prove_range_bp_batch(self.output_amounts, self.output_masks)
        self._mem_trace("post-bp" if __debug__ else None, collect=True)

        # Incremental hashing
        self.full_message_hasher.rsig_val(rsig, True, raw=False)
        self._mem_trace("post-bp-hash" if __debug__ else None, collect=True)

        rsig = misc.dump_rsig_bp(rsig)
        self._mem_trace(
            "post-bp-ser, size: %s" % len(rsig) if __debug__ else None, collect=True
        )

    elif not self.rsig_offload and not self.use_bulletproof:
        C, mask, rsig = ring_ct.prove_range_chunked(amount, mask)
        del (ring_ct)

        # Incremental hashing
        self.full_message_hasher.rsig_val(rsig, False, raw=True)
        self._check_out_commitment(amount, mask, C)

    elif self.rsig_offload and self.use_bulletproof:
        from apps.monero.xmr.serialize_messages.tx_rsig_bulletproof import Bulletproof

        masks = [
            self._get_out_mask(1 + idx - batch_size + ix) for ix in range(batch_size)
        ]

        bp_obj = misc.parse_msg(rsig_data.rsig, Bulletproof())
        rsig_data.rsig = None

        self.full_message_hasher.rsig_val(bp_obj, True, raw=False)
        res = ring_ct.verify_bp(bp_obj, self.output_amounts, masks)
        self.assrt(res, "BP verification fail")
        self._mem_trace("BP verified" if __debug__ else None, collect=True)
        del (bp_obj, ring_ct)

    elif self.rsig_offload and not self.use_bulletproof:
        self.full_message_hasher.rsig_val(rsig_data.rsig, False, raw=True)
        rsig_data.rsig = None

    else:
        raise misc.TrezorError("Unexpected rsig state")

    self._mem_trace("rproof" if __debug__ else None, collect=True)
    self.output_amounts = []
    if not self.rsig_offload:
        self.output_masks = []
    return rsig, mask


def _return_rsig_data(self, rsig):
    if rsig is None:
        return None
    from trezor.messages.MoneroTransactionRsigData import MoneroTransactionRsigData

    if isinstance(rsig, list):
        return MoneroTransactionRsigData(rsig_parts=rsig)
    else:
        return MoneroTransactionRsigData(rsig=rsig)


def _set_out1_ecdh(self, dest_pub_key, amount, mask, amount_key):
    from apps.monero.xmr import ring_ct

    # Mask sum
    out_pk = misc.StdObj(
        dest=crypto.encodepoint(dest_pub_key),
        mask=crypto.encodepoint(crypto.gen_commitment(mask, amount)),
    )
    self.sumout = crypto.sc_add(self.sumout, mask)
    self.output_sk.append(misc.StdObj(mask=mask))

    # ECDH masking
    from apps.monero.xmr.sub.recode import recode_ecdh

    ecdh_info = misc.StdObj(mask=mask, amount=crypto.sc_init(amount))
    ring_ct.ecdh_encode_into(
        ecdh_info, ecdh_info, derivation=crypto.encodeint(amount_key)
    )
    recode_ecdh(ecdh_info, encode=True)

    ecdh_info_bin = bytearray(64)
    utils.memcpy(ecdh_info_bin, 0, ecdh_info.mask, 0, 32)
    utils.memcpy(ecdh_info_bin, 32, ecdh_info.amount, 0, 32)
    gc.collect()

    return out_pk, ecdh_info_bin


def _set_out1_additional_keys(self, dst_entr):
    additional_txkey = None
    additional_txkey_priv = None
    if self.need_additional_txkeys:
        use_provided = self.num_dests() == len(self.additional_tx_private_keys)
        additional_txkey_priv = (
            self.additional_tx_private_keys[self.out_idx]
            if use_provided
            else crypto.random_scalar()
        )

        if dst_entr.is_subaddress:
            additional_txkey = crypto.scalarmult(
                crypto.decodepoint(dst_entr.addr.spend_public_key),
                additional_txkey_priv,
            )
        else:
            additional_txkey = crypto.scalarmult_base(additional_txkey_priv)

        self.additional_tx_public_keys.append(crypto.encodepoint(additional_txkey))
        if not use_provided:
            self.additional_tx_private_keys.append(additional_txkey_priv)
    return additional_txkey_priv


def _set_out1_derivation(self, dst_entr, additional_txkey_priv):
    from apps.monero.xmr.sub.addr import addr_eq

    change_addr = self.change_address()
    if change_addr and addr_eq(dst_entr.addr, change_addr):
        # sending change to yourself; derivation = a*R
        derivation = crypto.generate_key_derivation(
            self.r_pub, self.creds.view_key_private
        )

    else:
        # sending to the recipient; derivation = r*A (or s*C in the subaddress scheme)
        deriv_priv = (
            additional_txkey_priv
            if dst_entr.is_subaddress and self.need_additional_txkeys
            else self.r
        )
        derivation = crypto.generate_key_derivation(
            crypto.decodepoint(dst_entr.addr.view_public_key), deriv_priv
        )
    return derivation


def _check_out_commitment(self, amount, mask, C):
    self.assrt(
        crypto.point_eq(
            C,
            crypto.point_add(crypto.scalarmult_base(mask), crypto.scalarmult_h(amount)),
        ),
        "OutC fail",
    )


def _is_last_in_batch(self, idx, bidx=None):
    """
    Returns true if the current output is last in the rsig batch
    """
    bidx = self._get_rsig_batch(idx) if bidx is None else bidx
    batch_size = self.rsig_grp[bidx]
    return (idx - sum(self.rsig_grp[:bidx])) + 1 == batch_size


def _get_rsig_batch(self, idx):
    """
    Returns index of the current rsig batch
    """
    r = 0
    c = 0
    while c < idx + 1:
        c += self.rsig_grp[r]
        r += 1
    return r - 1


def _get_out_mask(self, idx):
    if self.rsig_offload:
        return self.output_masks[idx]
    else:
        is_last = idx + 1 == self.num_dests()
        if is_last:
            return crypto.sc_sub(self.sumpouts_alphas, self.sumout)
        else:
            return crypto.random_scalar()
