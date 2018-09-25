"""
Final message.
Offloading tx related data, encrypted.
"""

import gc

from .tsx_sign_builder import TransactionSigningState

from apps.monero.controller import misc
from apps.monero.xmr import common, crypto, monero


async def final_msg(self):
    """
    Final step after transaction signing.
    """
    from trezor.messages.MoneroTransactionFinalAck import MoneroTransactionFinalAck
    from apps.monero.xmr.enc import chacha_poly

    self.state.set_final()

    cout_key = self.enc_key_cout() if self.multi_sig else None

    # Encrypted tx keys under transaction specific key, derived from txhash and spend key.
    # Deterministic transaction key, so we can recover it just from transaction and the spend key.
    tx_key, salt, rand_mult = misc.compute_tx_key(
        self.creds.spend_key_private, self.tx_prefix_hash
    )

    key_buff = crypto.encodeint(self.r) + b"".join(
        [crypto.encodeint(x) for x in self.additional_tx_private_keys]
    )
    tx_enc_keys = chacha_poly.encrypt_pack(tx_key, key_buff)

    await self.iface.transaction_finished()
    gc.collect()

    return MoneroTransactionFinalAck(
        cout_key=cout_key, salt=salt, rand_mult=rand_mult, tx_enc_keys=tx_enc_keys
    )
