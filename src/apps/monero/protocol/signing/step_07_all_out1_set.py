"""
All outputs were set in this phase. Computes additional public keys (if needed), tx.extra and
transaction prefix hash.
Adds additional public keys to the tx.extra

:return: tx.extra, tx_prefix_hash
"""

import gc

from .tsx_sign_builder import TransactionSigningState

from apps.monero.controller import misc
from apps.monero.xmr import common, crypto, monero


async def all_out1_set(self):
    """
    All outputs were set in this phase. Computes additional public keys (if needed), tx.extra and
    transaction prefix hash.
    Adds additional public keys to the tx.extra

    :return: tx.extra, tx_prefix_hash
    """
    self._mem_trace(0)
    self.state.set_output_done()
    await self.iface.transaction_step(self.STEP_ALL_OUT)
    self._mem_trace(1)

    if self.out_idx + 1 != self.num_dests():
        raise ValueError("Invalid out num")

    # Test if \sum Alpha == \sum A
    if self.use_simple_rct:
        self.assrt(crypto.sc_eq(self.sumout, self.sumpouts_alphas))

    # Fee test
    if self.fee != (self.summary_inputs_money - self.summary_outs_money):
        raise ValueError(
            "Fee invalid %s vs %s, out: %s"
            % (
                self.fee,
                self.summary_inputs_money - self.summary_outs_money,
                self.summary_outs_money,
            )
        )
    self._mem_trace(2)

    # Set public key to the extra
    # Not needed to remove - extra is clean
    self.all_out1_set_tx_extra()
    self.additional_tx_public_keys = None

    gc.collect()
    self._mem_trace(3)

    if self.summary_outs_money > self.summary_inputs_money:
        raise ValueError(
            "Transaction inputs money (%s) less than outputs money (%s)"
            % (self.summary_inputs_money, self.summary_outs_money)
        )

    # Hashing transaction prefix
    self.all_out1_set_tx_prefix()
    extra_b = self.tx.extra
    self.tx = None
    gc.collect()
    self._mem_trace(4)

    # Txprefix match check for multisig
    if not common.is_empty(self.exp_tx_prefix_hash) and not common.ct_equal(
        self.exp_tx_prefix_hash, self.tx_prefix_hash
    ):
        self.state.set_fail()
        # todo   raise wire.NotEnoughFunds(e.message) ??
        raise misc.TrezorTxPrefixHashNotMatchingError("Tx prefix invalid")

    gc.collect()
    self._mem_trace(5)

    from trezor.messages.MoneroRingCtSig import MoneroRingCtSig
    from trezor.messages.MoneroTransactionAllOutSetAck import (
        MoneroTransactionAllOutSetAck
    )

    rv = self.init_rct_sig()
    rv_pb = MoneroRingCtSig(txn_fee=rv.txnFee, message=rv.message, rv_type=rv.type)
    return MoneroTransactionAllOutSetAck(
        extra=extra_b, tx_prefix_hash=self.tx_prefix_hash, rv=rv_pb
    )


def all_out1_set_tx_extra(self):
    from apps.monero.xmr.sub import tsx_helper

    self.tx.extra = tsx_helper.add_tx_pub_key_to_extra(self.tx.extra, self.r_pub)

    # Not needed to remove - extra is clean
    # self.tx.extra = await monero.remove_field_from_tx_extra(self.tx.extra, xmrtypes.TxExtraAdditionalPubKeys)
    if self.need_additional_txkeys:
        self.tx.extra = tsx_helper.add_additional_tx_pub_keys_to_extra(
            self.tx.extra, pub_enc=self.additional_tx_public_keys
        )


def all_out1_set_tx_prefix(self):
    from apps.monero.xmr.serialize.message_types import BlobType

    self.tx_prefix_hasher.message_field(self.tx, ("extra", BlobType))  # extra

    self.tx_prefix_hash = self.tx_prefix_hasher.get_digest()
    self.tx_prefix_hasher = None

    # Hash message to the final_message
    self.full_message_hasher.set_message(self.tx_prefix_hash)


def init_rct_sig(self):
    """
    Initializes RCTsig structure (fee, tx prefix hash, type)
    """
    rv = misc.StdObj(
        txnFee=self.get_fee(), message=self.tx_prefix_hash, type=self.get_rct_type()
    )
    return rv
