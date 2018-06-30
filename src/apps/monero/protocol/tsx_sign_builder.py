import gc
from trezor import log
import micropython
from micropython import const

from apps.monero.controller import misc
from apps.monero.xmr import crypto, common, monero


class TprefixStub(object):
    __slots__ = ('version', 'unlock_time', 'vin', 'vout', 'extra')

    def __init__(self, **kwargs):
        for kw in kwargs:
            setattr(self, kw, kwargs[kw])


class TTransactionBuilder(object):
    """
    Transaction builder
    """

    STEP_INP = const(100)
    STEP_PERM = const(200)
    STEP_VINI = const(300)
    STEP_OUT = const(400)
    STEP_ALL_OUT = const(500)
    STEP_MLSAG = const(600)
    STEP_SIGN = const(700)

    def __init__(self, trezor=None, creds=None, **kwargs):
        from apps.monero.xmr.sub.keccak_hasher import KeccakArchive
        from apps.monero.xmr.sub.mlsag_hasher import PreMlsagHasher
        from apps.monero.protocol.tsx_sign_state import TState

        self.trezor = trezor
        self.creds = creds
        self.key_master = None
        self.key_hmac = None
        self.key_enc = None

        self.r = None  # txkey
        self.r_pub = None
        self.state = TState()

        self.multi_sig = False
        self.need_additional_txkeys = False
        self.use_bulletproof = False
        self.use_rct = True
        self.use_simple_rct = False
        self.input_count = 0
        self.output_count = 0
        self.output_change = None
        self.mixin = 0
        self.fee = 0

        self.additional_tx_private_keys = []
        self.additional_tx_public_keys = []
        self.inp_idx = -1
        self.out_idx = -1
        self.summary_inputs_money = 0
        self.summary_outs_money = 0
        self.input_secrets = []
        self.input_alphas = []
        self.input_pseudo_outs = []
        self.output_sk = []
        self.output_pk = []
        self.sumout = crypto.sc_0()
        self.sumpouts_alphas = crypto.sc_0()
        self.subaddresses = {}
        self.tx = TprefixStub(vin=[], vout=[], extra=b'')
        self.source_permutation = []  # sorted by key images
        self.tx_prefix_hasher = KeccakArchive()
        self.tx_prefix_hash = None
        self.full_message_hasher = PreMlsagHasher()
        self.full_message = None
        self.exp_tx_prefix_hash = None

    def assrt(self, condition, msg=None):
        """
        Asserts condition
        :param condition:
        :param msg:
        :return:
        """
        if condition:
            return
        raise ValueError('Assertion error%s' % (' : %s' % msg if msg else ''))

    def is_terminal(self):
        """
        Returns true if the state is terminal
        :return:
        """
        return self.state.is_terminal()

    def gen_r(self, use_r=None):
        """
        Generates a new transaction key pair.
        :param use_r:
        :return:
        """
        self.r = crypto.random_scalar() if use_r is None else use_r
        self.r_pub = crypto.scalarmult_base(self.r)

    def check_change(self, outputs):
        """
        Checks if the change address is among tx outputs.
        :param outputs:
        :return:
        """
        change_addr = self.change_address()
        if change_addr is None:
            return

        for out in outputs:
            if out.addr == change_addr:
                return True

        raise ValueError('Change address not found in outputs')

    def in_memory(self):
        """
        Returns true if the input transaction can be processed whole in-memory
        :return:
        """
        return False and self.input_count <= 1

    def num_inputs(self):
        """
        Number of inputs
        :return:
        """
        return self.input_count

    def num_dests(self):
        """
        Number of destinations
        :return:
        """
        return self.output_count

    def get_fee(self):
        """
        Txn fee
        :return:
        """
        return self.fee if self.fee > 0 else 0

    def change_address(self):
        """
        Returns change address if change dst is set
        :return:
        """
        return self.output_change.addr if self.output_change else None

    def get_rct_type(self):
        """
        RCTsig type (simple/full x Borromean/Bulletproof)
        :return:
        """
        from apps.monero.xmr.serialize_messages.tx_rsig import RctType
        if self.use_simple_rct:
            return RctType.SimpleBulletproof if self.use_bulletproof else RctType.Simple
        else:
            return RctType.FullBulletproof if self.use_bulletproof else RctType.Full

    def init_rct_sig(self):
        """
        Initializes RCTsig structure (fee, tx prefix hash, type)
        :return:
        """
        from apps.monero.xmr.serialize_messages.tx_full import RctSig

        rv = RctSig()
        # rv.p = RctSigPrunable()
        rv.txnFee = self.get_fee()
        rv.message = self.tx_prefix_hash
        rv.type = self.get_rct_type()
        return rv

    def hmac_key_txin(self, idx):
        """
        (TxSourceEntry[i] || tx.vin[i]) hmac key
        :param idx:
        :return:
        """
        from apps.monero.xmr.serialize.int_serialize import dump_uvarint_b
        return crypto.keccak_2hash(self.key_hmac + b'txin' + dump_uvarint_b(idx))

    def hmac_key_txin_comm(self, idx):
        """
        pseudo_outputs[i] hmac key. Pedersen commitment for inputs.
        :param idx:
        :return:
        """
        from apps.monero.xmr.serialize.int_serialize import dump_uvarint_b
        return crypto.keccak_2hash(self.key_hmac + b'txin-comm' + dump_uvarint_b(idx))

    def hmac_key_txdst(self, idx):
        """
        TxDestinationEntry[i] hmac key
        :param idx:
        :return:
        """
        from apps.monero.xmr.serialize.int_serialize import dump_uvarint_b
        return crypto.keccak_2hash(self.key_hmac + b'txdest' + dump_uvarint_b(idx))

    def hmac_key_txout(self, idx):
        """
        (TxDestinationEntry[i] || tx.vout[i]) hmac key
        :param idx:
        :return:
        """
        from apps.monero.xmr.serialize.int_serialize import dump_uvarint_b
        return crypto.keccak_2hash(self.key_hmac + b'txout' + dump_uvarint_b(idx))

    def hmac_key_txout_asig(self, idx):
        """
        rsig[i] hmac key. Range signature HMAC
        :param idx:
        :return:
        """
        from apps.monero.xmr.serialize.int_serialize import dump_uvarint_b
        return crypto.keccak_2hash(self.key_hmac + b'txout-asig' + dump_uvarint_b(idx))

    def enc_key_txin_alpha(self, idx):
        """
        AES-GCM encryption key for alpha[i] used in Pedersen commitment in pseudo_outs[i]
        :param idx:
        :return:
        """
        from apps.monero.xmr.serialize.int_serialize import dump_uvarint_b
        return crypto.keccak_2hash(self.key_enc + b'txin-alpha' + dump_uvarint_b(idx))

    def enc_key_cout(self, idx=None):
        """
        AES-GCM encryption key for multisig C values from MLASG.
        :param idx:
        :return:
        """
        from apps.monero.xmr.serialize.int_serialize import dump_uvarint_b
        return crypto.keccak_2hash(self.key_enc + b'cout' + (dump_uvarint_b(idx) if idx else b''))

    async def gen_hmac_vini(self, src_entr, vini, idx):
        """
        Computes hmac (TxSourceEntry[i] || tx.vin[i])
        :param src_entr:
        :param vini:
        :param idx:
        :return:
        """
        from apps.monero.xmr.sub.keccak_hasher import get_keccak_writer
        from apps.monero.xmr.serialize import xmrserialize
        from apps.monero.xmr.serialize_messages.tx_src_entry import TxSourceEntry
        from apps.monero.xmr.serialize_messages.tx_prefix import TxinToKey

        kwriter = get_keccak_writer()
        ar = xmrserialize.Archive(kwriter, True)
        await ar.message(src_entr, TxSourceEntry)
        await ar.message(vini, TxinToKey)

        hmac_key_vini = self.hmac_key_txin(idx)
        hmac_vini = crypto.compute_hmac(hmac_key_vini, kwriter.get_digest())
        return hmac_vini

    async def gen_hmac_vouti(self, dst_entr, tx_out, idx):
        """
        Generates HMAC for (TxDestinationEntry[i] || tx.vout[i])
        :param dst_entr:
        :param tx_out:
        :param idx:
        :return:
        """
        from apps.monero.xmr.sub.keccak_hasher import get_keccak_writer
        from apps.monero.xmr.serialize import xmrserialize
        from apps.monero.xmr.serialize_messages.tx_dest_entry import TxDestinationEntry
        from apps.monero.xmr.serialize_messages.tx_prefix import TxOut

        kwriter = get_keccak_writer()
        ar = xmrserialize.Archive(kwriter, True)
        await ar.message(dst_entr, TxDestinationEntry)
        await ar.message(tx_out, TxOut)

        hmac_key_vouti = self.hmac_key_txout(idx)
        hmac_vouti = crypto.compute_hmac(hmac_key_vouti, kwriter.get_digest())
        return hmac_vouti

    async def gen_hmac_tsxdest(self, dst_entr, idx):
        """
        Generates HMAC for TxDestinationEntry[i]
        :param dst_entr:
        :param idx:
        :return:
        """
        from apps.monero.xmr.sub.keccak_hasher import get_keccak_writer
        from apps.monero.xmr.serialize import xmrserialize
        from apps.monero.xmr.serialize_messages.tx_dest_entry import TxDestinationEntry

        kwriter = get_keccak_writer()
        ar = xmrserialize.Archive(kwriter, True)
        await ar.message(dst_entr, TxDestinationEntry)

        hmac_key = self.hmac_key_txdst(idx)
        hmac_tsxdest = crypto.compute_hmac(hmac_key, kwriter.get_digest())
        return hmac_tsxdest

    async def _tprefix_update(self):
        from apps.monero.xmr.serialize_messages.tx_prefix import TransactionPrefix
        tx_fields = TransactionPrefix.f_specs()
        await self.tx_prefix_hasher.ar.message_field(self.tx, tx_fields[0])
        await self.tx_prefix_hasher.ar.message_field(self.tx, tx_fields[1])
        await self.tx_prefix_hasher.ar.container_size(self.num_inputs(), tx_fields[2][1])
        log.debug(__name__, '### 5Mem Free: {} Allocated: {}'.format(gc.mem_free(), gc.mem_alloc()))

    async def init_transaction(self, tsx_data, tsx_ctr):
        """
        Initializes a new transaction.
        :param tsx_data:
        :type tsx_data: TsxData
        :param tsx_ctr:
        :return:
        """
        from apps.monero.xmr.sub.addr import classify_subaddresses

        log.debug(__name__, '### BLD 0Mem Free: {} Allocated: {}'.format(gc.mem_free(), gc.mem_alloc()))
        self.gen_r()
        self.state.init_tsx()

        log.debug(__name__, '### 1Mem Free: {} Allocated: {}'.format(gc.mem_free(), gc.mem_alloc()))

        # Ask for confirmation
        confirmation = await self.trezor.iface.confirm_transaction(tsx_data, self.creds)
        if not confirmation:
            from trezor.messages.MoneroRespError import MoneroRespError
            return MoneroRespError(reason='rejected')

        gc.collect()
        log.debug(__name__, '### 3Mem Free: {} Allocated: {}'.format(gc.mem_free(), gc.mem_alloc()))
        micropython.mem_info(1)

        # Basic transaction parameters
        self.input_count = tsx_data.num_inputs
        self.output_count = len(tsx_data.outputs)
        self.output_change = tsx_data.change_dts
        self.mixin = tsx_data.mixin
        self.fee = tsx_data.fee
        self.use_simple_rct = self.input_count > 1
        self.multi_sig = tsx_data.is_multisig
        self.state.inp_cnt(self.in_memory())
        self.check_change(tsx_data.outputs)
        self.exp_tx_prefix_hash = common.defval_empty(tsx_data.exp_tx_prefix_hash, None)

        # Provided tx key, used mostly in multisig.
        if len(tsx_data.use_tx_keys) > 0:
            for ckey in tsx_data.use_tx_keys:
                crypto.check_sc(crypto.decodeint(ckey))

            self.gen_r(use_r=crypto.decodeint(tsx_data.use_tx_keys[0]))
            self.additional_tx_private_keys = [crypto.decodeint(x) for x in tsx_data.use_tx_keys[1:]]

        # Additional keys w.r.t. subaddress destinations
        class_res = classify_subaddresses(tsx_data.outputs, self.change_address())
        num_stdaddresses, num_subaddresses, single_dest_subaddress = class_res

        # if this is a single-destination transfer to a subaddress, we set the tx pubkey to R=s*D
        if num_stdaddresses == 0 and num_subaddresses == 1:
            self.r_pub = crypto.ge_scalarmult(self.r, crypto.decodepoint(single_dest_subaddress.m_spend_public_key))

        self.need_additional_txkeys = num_subaddresses > 0 and (num_stdaddresses > 0 or num_subaddresses > 1)
        log.debug(__name__, '### 4Mem Free: {} Allocated: {}'.format(gc.mem_free(), gc.mem_alloc()))
        # Extra processing, payment id
        self.tx.version = 2
        self.tx.unlock_time = tsx_data.unlock_time
        await self.process_payment_id(tsx_data)
        await self.compute_sec_keys(tsx_data, tsx_ctr)
        gc.collect()

        # Iterative tx_prefix_hash hash computation
        await self._tprefix_update()
        gc.collect()

        # Final message hasher
        self.full_message_hasher.init(self.use_simple_rct)
        await self.full_message_hasher.set_type_fee(self.get_rct_type(), self.get_fee())

        # Sub address precomputation
        if tsx_data.account is not None and tsx_data.minor_indices:
            self.precompute_subaddr(tsx_data.account, tsx_data.minor_indices)

        # HMAC outputs - pinning
        hmacs = []
        for idx in range(self.num_dests()):
            c_hmac = await self.gen_hmac_tsxdest(tsx_data.outputs[idx], idx)
            hmacs.append(c_hmac)
        log.debug(__name__, '### 6Mem Free: {} Allocated: {}'.format(gc.mem_free(), gc.mem_alloc()))

        from trezor.messages.MoneroTsxInitResp import MoneroTsxInitResp
        return MoneroTsxInitResp(in_memory=self.in_memory(), hmacs=hmacs)

    async def process_payment_id(self, tsx_data):
        """
        Payment id -> extra
        :return:
        """
        if common.is_empty(tsx_data.payment_id):
            return

        from apps.monero.xmr.sub import tsx_helper

        view_key_pub_enc = tsx_helper.get_destination_view_key_pub(tsx_data.outputs, self.change_address())
        if view_key_pub_enc == crypto.NULL_KEY_ENC:
            raise ValueError('Destinations have to have exactly one output to support encrypted payment ids')

        view_key_pub = crypto.decodepoint(view_key_pub_enc)
        payment_id_encr = tsx_helper.encrypt_payment_id(tsx_data.payment_id, view_key_pub, self.r)

        extra_nonce = tsx_helper.set_encrypted_payment_id_to_tx_extra_nonce(payment_id_encr)
        self.tx.extra = tsx_helper.add_extra_nonce_to_tx_extra(b'', extra_nonce)

    async def compute_sec_keys(self, tsx_data, tsx_ctr):
        """
        Generate master key H(TsxData || r || c_tsx)
        :return:
        """
        from apps.monero.xmr.sub.keccak_hasher import get_keccak_writer
        from apps.monero.xmr.serialize import xmrserialize

        writer = get_keccak_writer()
        ar1 = xmrserialize.Archive(writer, True)
        await ar1.message(tsx_data)
        await writer.awrite(crypto.encodeint(self.r))
        await xmrserialize.dump_uvarint(writer, tsx_ctr)
        self.key_master = crypto.keccak_2hash(writer.get_digest() + crypto.encodeint(crypto.random_scalar()))
        self.key_hmac = crypto.keccak_2hash(b'hmac' + self.key_master)
        self.key_enc = crypto.keccak_2hash(b'enc' + self.key_master)

    def precompute_subaddr(self, account, indices):
        """
        Precomputes subaddresses for account (major) and list of indices (minors)
        Subaddresses have to be stored in encoded form - unique representation.
        Single point can have multiple extended coordinates representation - would not match during subaddress search.
        :param account:
        :param indices:
        :return:
        """
        monero.compute_subaddresses(self.trezor.creds, account, indices, self.subaddresses)

    async def set_input(self, src_entr):
        """
        Sets UTXO one by one.
        Computes spending secret key, key image. tx.vin[i] + HMAC, Pedersen commitment on amount.

        If number of inputs is small, in-memory mode is used = alpha, pseudo_outs are kept in the Trezor.
        Otherwise pseudo_outs are offloaded with HMAC, alpha is offloaded encrypted under AES-GCM() with
        key derived for exactly this purpose.

        :param src_entr:
        :type src_entr: apps.monero.xmr.serialize_messages.tx_construct.TxSourceEntry
        :return:
        """
        from trezor.messages.MoneroTsxSetInputResp import MoneroTsxSetInputResp
        from apps.monero.xmr.enc import chacha_poly
        from apps.monero.xmr.sub import tsx_helper
        from apps.monero.xmr.serialize_messages.tx_prefix import TxinToKey

        self.state.input()
        self.inp_idx += 1

        await self.trezor.iface.transaction_step(self.STEP_INP, self.inp_idx)

        if self.inp_idx >= self.num_inputs():
            raise ValueError('Too many inputs')
        if src_entr.real_output >= len(src_entr.outputs):
            raise ValueError('real_output index %s bigger than output_keys.size() %s' % (src_entr.real_output, len(src_entr.outputs)))
        self.summary_inputs_money += src_entr.amount

        # Secrets derivation
        out_key = crypto.decodepoint(src_entr.outputs[src_entr.real_output][1].dest)
        tx_key = crypto.decodepoint(src_entr.real_out_tx_key)
        additional_keys = [crypto.decodepoint(x) for x in src_entr.real_out_additional_tx_keys]

        secs = monero.generate_key_image_helper(self.trezor.creds, self.subaddresses, out_key,
                                                tx_key,
                                                additional_keys,
                                                src_entr.real_output_in_tx_index)
        xi, ki, di = secs
        self.input_secrets.append(xi)

        # Construct tx.vin
        ki_real = src_entr.multisig_kLRki.ki if self.multi_sig else ki
        vini = TxinToKey(amount=src_entr.amount, k_image=crypto.encodepoint(ki_real))
        vini.key_offsets = [x[0] for x in src_entr.outputs]
        vini.key_offsets = tsx_helper.absolute_output_offsets_to_relative(vini.key_offsets)

        if src_entr.rct:
            vini.amount = 0

        if self.in_memory():
            self.tx.vin.append(vini)

        # HMAC(T_in,i || vin_i)
        hmac_vini = await self.gen_hmac_vini(src_entr, vini, self.inp_idx)

        # PseudoOuts commitment, alphas stored to state
        pseudo_out = None
        pseudo_out_hmac = None
        alpha_enc = None
        if self.use_simple_rct:
            alpha, pseudo_out = await self.commitment(src_entr.amount)
            pseudo_out = crypto.encodepoint(pseudo_out)

            # In full version the alpha is encrypted and passed back for storage
            if self.in_memory():
                self.input_alphas.append(alpha)
                self.input_pseudo_outs.append(pseudo_out)
            else:
                pseudo_out_hmac = crypto.compute_hmac(self.hmac_key_txin_comm(self.inp_idx), pseudo_out)
                alpha_enc = chacha_poly.encrypt_pack(self.enc_key_txin_alpha(self.inp_idx), crypto.encodeint(alpha))

        # All inputs done?
        if self.inp_idx + 1 == self.num_inputs():
            await self.tsx_inputs_done()

        return MoneroTsxSetInputResp(vini=await misc.dump_msg(vini, preallocate=64),
                                     vini_hmac=hmac_vini,
                                     pseudo_out=pseudo_out,
                                     pseudo_out_hmac=pseudo_out_hmac,
                                     alpha_enc=alpha_enc)

    async def tsx_inputs_done(self):
        """
        All inputs set
        :return:
        """
        self.state.input_done()
        del self.subaddresses

        if self.inp_idx + 1 != self.num_inputs():
            raise ValueError('Input count mismatch')

        if self.in_memory():
            return await self.tsx_inputs_done_inm()

    async def tsx_inputs_done_inm(self):
        """
        In-memory post processing - tx.vin[i] sorting by key image.
        Used only if number of inputs is small - computable in Trezor without offloading.

        :return:
        """
        # Sort tx.in by key image
        self.source_permutation = list(range(self.num_inputs()))
        self.source_permutation.sort(key=lambda x: self.tx.vin[x].k_image, reverse=True)
        await self._tsx_inputs_permutation(self.source_permutation)

    async def tsx_inputs_permutation(self, permutation):
        """
        Set permutation on the inputs - sorted by key image on host.

        :param permutation:
        :return:
        """
        from trezor.messages.MoneroTsxInputsPermutationResp import MoneroTsxInputsPermutationResp
        await self.trezor.iface.transaction_step(self.STEP_PERM)

        if self.in_memory():
            return
        await self._tsx_inputs_permutation(permutation)
        return MoneroTsxInputsPermutationResp()

    async def _tsx_inputs_permutation(self, permutation):
        """
        Set permutation on the inputs - sorted by key image on host.

        :param permutation:
        :return:
        """
        self.state.input_permutation()
        self.source_permutation = permutation

        def swapper(x, y):
            self.input_secrets[x], self.input_secrets[y] = self.input_secrets[y], self.input_secrets[x]
            if self.in_memory() and self.use_simple_rct:
                self.input_alphas[x], self.input_alphas[y] = self.input_alphas[y], self.input_alphas[x]
                self.input_pseudo_outs[x], self.input_pseudo_outs[y] = self.input_pseudo_outs[y], self.input_pseudo_outs[x]
            if self.in_memory():
                self.tx.vin[x], self.tx.vin[y] = self.tx.vin[y], self.tx.vin[x]

        common.apply_permutation(self.source_permutation, swapper)
        self.inp_idx = -1

        # Incremental hashing
        if self.in_memory():
            for idx in range(self.num_inputs()):
                await self.hash_vini_pseudo_out(self.tx.vin[idx], idx)

    async def input_vini(self, src_entr, vini, hmac, pseudo_out, pseudo_out_hmac):
        """
        Set tx.vin[i] for incremental tx prefix hash computation.
        After sorting by key images on host.
        Hashes pseudo_out to the final_message.

        :param src_entr:
        :param vini: tx.vin[i]
        :param hmac: HMAC of tx.vin[i]
        :param pseudo_out: pseudo_out for the current entry
        :param pseudo_out_hmac: hmac of pseudo_out
        :return:
        """
        from trezor.messages.MoneroTsxInputViniResp import MoneroTsxInputViniResp
        await self.trezor.iface.transaction_step(self.STEP_VINI, self.inp_idx + 1)

        if self.in_memory():
            return
        if self.inp_idx >= self.num_inputs():
            raise ValueError('Too many inputs')

        self.state.input_vins()
        self.inp_idx += 1

        # HMAC(T_in,i || vin_i)
        hmac_vini = await self.gen_hmac_vini(src_entr, vini, self.source_permutation[self.inp_idx])
        if not common.ct_equal(hmac_vini, hmac):
            raise ValueError('HMAC is not correct')

        await self.hash_vini_pseudo_out(vini, self.inp_idx, pseudo_out, pseudo_out_hmac)
        return MoneroTsxInputViniResp()

    async def hash_vini_pseudo_out(self, vini, inp_idx, pseudo_out=None, pseudo_out_hmac=None):
        """
        Incremental hasing of tx.vin[i] and pseudo output
        :param vini:
        :param inp_idx:
        :param pseudo_out:
        :param pseudo_out_hmac:
        :return:
        """
        # Serialize particular input type
        from apps.monero.xmr.serialize import xmrserialize
        from apps.monero.xmr.serialize_messages.tx_prefix import TxInV
        self.tx_prefix_hasher.refresh(xser=xmrserialize)

        await self.tx_prefix_hasher.ar.field(vini, TxInV)

        # Pseudo_out incremental hashing - applicable only in simple rct
        if not self.use_simple_rct:
            return

        if not self.in_memory():
            idx = self.source_permutation[inp_idx]
            pseudo_out_hmac_comp = crypto.compute_hmac(self.hmac_key_txin_comm(idx), pseudo_out)
            if not common.ct_equal(pseudo_out_hmac, pseudo_out_hmac_comp):
                raise ValueError('HMAC invalid for pseudo outs')
        else:
            pseudo_out = self.input_pseudo_outs[inp_idx]

        await self.full_message_hasher.set_pseudo_out(pseudo_out)

    async def commitment(self, in_amount):
        """
        Computes Pedersen commitment - pseudo outs
        Here is slight deviation from the original protocol.
        We want that \sum Alpha = \sum A_{i,j} where A_{i,j} is a mask from range proof for output i, bit j.

        Previously this was computed in such a way that Alpha_{last} = \sum A{i,j} - \sum_{i=0}^{last-1} Alpha
        But we would prefer to compute commitment before range proofs so alphas are generated completely randomly
        and the last A mask is computed in this special way.
        Returns pseudo_out
        :return:
        """
        alpha = crypto.random_scalar()
        self.sumpouts_alphas = crypto.sc_add(self.sumpouts_alphas, alpha)
        return alpha, crypto.gen_c(alpha, in_amount)

    async def range_proof(self, idx, dest_pub_key, amount, amount_key):
        """
        Computes rangeproof and related information - out_sk, out_pk, ecdh_info.
        In order to optimize incremental transaction build, the mask computation is changed compared
        to the official Monero code. In the official code, the input pedersen commitments are computed
        after range proof in such a way summed masks for commitments (alpha) and rangeproofs (ai) are equal.

        In order to save roundtrips we compute commitments randomly and then for the last rangeproof
        a[63] = (\sum_{i=0}^{num_inp}alpha_i - \sum_{i=0}^{num_outs-1} amasks_i) - \sum_{i=0}^{62}a_i

        The range proof is incrementally hashed to the final_message.

        :param idx:
        :param dest_pub_key:
        :param amount:
        :param amount_key:
        :return:
        """
        from apps.monero.xmr import ring_ct
        from apps.monero.xmr.serialize_messages.ct_keys import CtKey
        from apps.monero.xmr.serialize_messages.tx_ecdh import EcdhTuple

        out_pk = CtKey(dest=dest_pub_key)
        is_last = idx + 1 == self.num_dests()
        last_mask = None if not is_last or not self.use_simple_rct else crypto.sc_sub(self.sumpouts_alphas, self.sumout)

        # Pedersen commitment on the value, mask from the commitment, range signature.
        C, mask, rsig = None, 0, None

        # Rangeproof
        gc.collect()
        if self.use_bulletproof:
            raise ValueError('Bulletproof not yet supported')

        else:
            C, mask, rsig = ring_ct.prove_range(amount, last_mask, backend_impl=True, byte_enc=True)

            self.assrt(crypto.point_eq(C, crypto.point_add(
                crypto.scalarmult_base(mask),
                crypto.scalarmult_h(amount))), 'rproof')

            # Incremental hashing
            await self.full_message_hasher.rsig_val(rsig, self.use_bulletproof, raw=True)
        gc.collect()

        # Mask sum
        out_pk.mask = crypto.encodepoint(C)
        self.sumout = crypto.sc_add(self.sumout, mask)
        self.output_sk.append(CtKey(mask=mask))

        # ECDH masking
        from apps.monero.xmr.sub.recode import recode_ecdh
        ecdh_info = EcdhTuple(mask=mask, amount=crypto.sc_init(amount))
        ecdh_info = ring_ct.ecdh_encode(ecdh_info, derivation=crypto.encodeint(amount_key))
        recode_ecdh(ecdh_info, encode=True)
        gc.collect()

        return rsig, out_pk, ecdh_info

    async def _set_out1_prefix(self):
        from apps.monero.xmr.serialize_messages.tx_prefix import TransactionPrefix
        await self.tx_prefix_hasher.ar.container_size(self.num_dests(), TransactionPrefix.f_specs()[3][1])

    async def set_out1(self, dst_entr, dst_entr_hmac):
        """
        Set destination entry one by one.
        Computes destination stealth address, amount key, range proof + HMAC, out_pk, ecdh_info.

        :param dst_entr
        :type dst_entr: TxDestinationEntry
        :param dst_entr_hmac
        :return:
        """
        from apps.monero.xmr.serialize import xmrserialize

        await self.trezor.iface.transaction_step(self.STEP_OUT, self.out_idx + 1)

        if self.state.is_input_vins() and self.inp_idx + 1 != self.num_inputs():
            raise ValueError('Invalid number of inputs')

        self.state.set_output()
        self.out_idx += 1
        change_addr = self.change_address()

        if dst_entr.amount <= 0 and self.tx.version <= 1:
            raise ValueError('Destination with wrong amount: %s' % dst_entr.amount)

        # HMAC check of the destination
        dst_entr_hmac_computed = await self.gen_hmac_tsxdest(dst_entr, self.out_idx)
        if not common.ct_equal(dst_entr_hmac, dst_entr_hmac_computed):
            raise ValueError('HMAC invalid')
        gc.collect()

        # First output - tx prefix hasher - size of the container
        self.tx_prefix_hasher.refresh(xser=xmrserialize)
        if self.out_idx == 0:
            await self._set_out1_prefix()
        gc.collect()

        additional_txkey = None
        additional_txkey_priv = None
        if self.need_additional_txkeys:
            use_provided = self.num_dests() == len(self.additional_tx_private_keys)
            additional_txkey_priv = self.additional_tx_private_keys[self.out_idx] if use_provided else crypto.random_scalar()

            if dst_entr.is_subaddress:
                additional_txkey = crypto.ge_scalarmult(additional_txkey_priv,
                                                        crypto.decodepoint(dst_entr.addr.m_spend_public_key))
            else:
                additional_txkey = crypto.ge_scalarmult_base(additional_txkey_priv)

            self.additional_tx_public_keys.append(crypto.encodepoint(additional_txkey))
            if not use_provided:
                self.additional_tx_private_keys.append(additional_txkey_priv)

        if change_addr and dst_entr.addr == change_addr:
            # sending change to yourself; derivation = a*R
            derivation = monero.generate_key_derivation(self.r_pub, self.creds.view_key_private)

        else:
            # sending to the recipient; derivation = r*A (or s*C in the subaddress scheme)
            deriv_priv = additional_txkey_priv if dst_entr.is_subaddress and self.need_additional_txkeys else self.r
            derivation = monero.generate_key_derivation(crypto.decodepoint(dst_entr.addr.m_view_public_key), deriv_priv)

        gc.collect()
        amount_key = crypto.derivation_to_scalar(derivation, self.out_idx)
        tx_out_key = crypto.derive_public_key(derivation, self.out_idx, crypto.decodepoint(dst_entr.addr.m_spend_public_key))

        from apps.monero.xmr.serialize_messages.tx_prefix import TxoutToKey
        from apps.monero.xmr.serialize_messages.tx_prefix import TxOut
        tk = TxoutToKey(key=crypto.encodepoint(tx_out_key))
        tx_out = TxOut(amount=0, target=tk)
        self.summary_outs_money += dst_entr.amount

        # Tx header prefix hashing
        await self.tx_prefix_hasher.ar.field(tx_out, TxOut)
        gc.collect()

        # Hmac dest_entr.
        hmac_vouti = await self.gen_hmac_vouti(dst_entr, tx_out, self.out_idx)
        gc.collect()

        # Range proof, out_pk, ecdh_info
        rsig, out_pk, ecdh_info = await self.range_proof(self.out_idx, dest_pub_key=tk.key, amount=dst_entr.amount, amount_key=amount_key)
        gc.collect()

        # Incremental hashing of the ECDH info.
        # RctSigBase allows to hash only one of the (ecdh, out_pk) as they are serialized
        # as whole vectors. Hashing ECDH info saves state space.
        await self.full_message_hasher.set_ecdh(ecdh_info)

        # Output_pk is stored to the state as it is used during the signature and hashed to the
        # RctSigBase later.
        self.output_pk.append(out_pk)
        gc.collect()
        from trezor.messages.MoneroTsxSetOutputResp import MoneroTsxSetOutputResp
        return MoneroTsxSetOutputResp(tx_out=await misc.dump_msg(tx_out, preallocate=34),
                                      vouti_hmac=hmac_vouti, rsig=rsig,  # rsig is already byte-encoded
                                      out_pk=await misc.dump_msg(out_pk, preallocate=64),
                                      ecdh_info=await misc.dump_msg(ecdh_info, preallocate=64))

    async def all_out1_set(self):
        """
        All outputs were set in this phase. Computes additional public keys (if needed), tx.extra and
        transaction prefix hash.
        Adds additional public keys to the tx.extra

        :return: tx.extra, tx_prefix_hash
        """
        from apps.monero.xmr.sub import tsx_helper

        self.state.set_output_done()
        await self.trezor.iface.transaction_step(self.STEP_ALL_OUT)

        if self.out_idx + 1 != self.num_dests():
            raise ValueError('Invalid out num')

        # Test if \sum Alpha == \sum A
        if self.use_simple_rct:
            self.assrt(crypto.sc_eq(self.sumout, self.sumpouts_alphas))

        # Fee test
        if self.fee != (self.summary_inputs_money - self.summary_outs_money):
            raise ValueError('Fee invalid')

        # Set public key to the extra
        # Not needed to remove - extra is clean
        # self.tx.extra = await monero.remove_field_from_tx_extra(self.tx.extra, xmrtypes.TxExtraPubKey)
        self.tx.extra = tsx_helper.add_tx_pub_key_to_extra(self.tx.extra, self.r_pub)

        # Not needed to remove - extra is clean
        # self.tx.extra = await monero.remove_field_from_tx_extra(self.tx.extra, xmrtypes.TxExtraAdditionalPubKeys)
        if self.need_additional_txkeys:
            self.tx.extra = await tsx_helper.add_additional_tx_pub_keys_to_extra(self.tx.extra, pub_enc=self.additional_tx_public_keys)

        if self.summary_outs_money > self.summary_inputs_money:
            raise ValueError('Transaction inputs money (%s) less than outputs money (%s)'
                             % (self.summary_inputs_money, self.summary_outs_money))

        # Hashing transaction prefix
        from apps.monero.xmr.serialize_messages.tx_prefix import TransactionPrefixExtraBlob
        await self.tx_prefix_hasher.ar.message_field(self.tx, TransactionPrefixExtraBlob.f_specs()[4])  # extra

        self.tx_prefix_hash = self.tx_prefix_hasher.kwriter.get_digest()
        del self.tx_prefix_hasher

        # Hash message to the final_message
        await self.full_message_hasher.set_message(self.tx_prefix_hash)
        rv = self.init_rct_sig()

        # Txprefix match check for multisig
        if not common.is_empty(self.exp_tx_prefix_hash) and \
                not common.ct_equal(self.exp_tx_prefix_hash, self.tx_prefix_hash):
            self.state.set_fail()
            raise misc.TrezorTxPrefixHashNotMatchingError('Tx prefix invalid')

        from trezor.messages.MoneroRctSig import MoneroRctSig
        from trezor.messages.MoneroTsxAllOutSetResp import MoneroTsxAllOutSetResp

        rv_pb = MoneroRctSig(txn_fee=rv.txnFee, message=rv.message, rv_type=rv.type)
        extra_b = self.tx.extra
        del self.tx
        del self.additional_tx_public_keys

        return MoneroTsxAllOutSetResp(extra=extra_b, tx_prefix_hash=self.tx_prefix_hash, rv=rv_pb)

    async def tsx_mlsag_ecdh_info(self):
        """
        Sets ecdh info for the incremental hashing mlsag.

        :return:
        """
        pass

    async def tsx_mlsag_out_pk(self):
        """
        Sets out_pk for the incremental hashing mlsag.

        :return:
        """
        if self.num_dests() != len(self.output_pk):
            raise ValueError('Invalid number of ecdh')

        for out in self.output_pk:
            await self.full_message_hasher.set_out_pk(out)

    async def mlsag_done(self):
        """
        MLSAG message computed.

        :return:
        """
        from trezor.messages.MoneroTsxMlsagDoneResp import MoneroTsxMlsagDoneResp

        self.state.set_final_message_done()
        await self.trezor.iface.transaction_step(self.STEP_MLSAG)

        await self.tsx_mlsag_ecdh_info()
        await self.tsx_mlsag_out_pk()
        await self.full_message_hasher.rctsig_base_done()
        self.out_idx = -1
        self.inp_idx = -1

        self.full_message = await self.full_message_hasher.get_digest()
        del self.full_message_hasher

        return MoneroTsxMlsagDoneResp(full_message_hash=self.full_message)

    async def sign_input(self, src_entr, vini, hmac_vini, pseudo_out, pseudo_out_hmac, alpha):
        """
        Generates a signature for one input.

        :param src_entr: Source entry
        :type src_entr: apps.monero.xmr.serialize_messages.tx_construct.TxSourceEntry
        :param vini: tx.vin[i] for the transaction. Contains key image, offsets, amount (usually zero)
        :param hmac_vini: HMAC for the tx.vin[i] as returned from Trezor
        :param pseudo_out: pedersen commitment for the current input, uses alpha as the mask.
        Only in memory offloaded scenario. Tuple containing HMAC, as returned from the Trezor.
        :param pseudo_out_hmac:
        :param alpha: alpha mask for the current input. Only in memory offloaded scenario,
        tuple as returned from the Trezor
        :return: Generated signature MGs[i]
        """
        self.state.set_signature()
        await self.trezor.iface.transaction_step(self.STEP_SIGN)

        self.inp_idx += 1
        if self.inp_idx >= self.num_inputs():
            raise ValueError('Invalid ins')
        if self.use_simple_rct and (not self.in_memory() and alpha is None):
            raise ValueError('Inconsistent1')
        if self.use_simple_rct and (not self.in_memory() and pseudo_out is None):
            raise ValueError('Inconsistent2')
        if self.inp_idx >= 1 and not self.use_simple_rct:
            raise ValueError('Inconsistent3')

        inv_idx = self.source_permutation[self.inp_idx]

        # Check HMAC of all inputs
        hmac_vini_comp = await self.gen_hmac_vini(src_entr, vini, inv_idx)
        if not common.ct_equal(hmac_vini_comp, hmac_vini):
            raise ValueError('HMAC is not correct')

        gc.collect()
        if self.use_simple_rct and not self.in_memory():
            pseudo_out_hmac_comp = crypto.compute_hmac(self.hmac_key_txin_comm(inv_idx), pseudo_out)
            if not common.ct_equal(pseudo_out_hmac_comp, pseudo_out_hmac):
                raise ValueError('HMAC is not correct')

            gc.collect()
            from apps.monero.xmr.enc import chacha_poly
            alpha_c = chacha_poly.decrypt_pack(self.enc_key_txin_alpha(inv_idx), bytes(alpha))
            alpha_c = crypto.decodeint(alpha_c)
            pseudo_out_c = crypto.decodepoint(pseudo_out)

        elif self.use_simple_rct:
            alpha_c = self.input_alphas[self.inp_idx]
            pseudo_out_c = crypto.decodepoint(self.input_pseudo_outs[self.inp_idx])

        else:
            alpha_c = None
            pseudo_out_c = None

        gc.collect()
        # Basic setup, sanity check
        index = src_entr.real_output
        in_sk = misc.StdObj(dest=self.input_secrets[self.inp_idx], mask=crypto.decodeint(src_entr.mask))
        kLRki = src_entr.multisig_kLRki if self.multi_sig else None

        # Private key correctness test
        self.assrt(crypto.point_eq(crypto.decodepoint(src_entr.outputs[src_entr.real_output][1].dest),
                                   crypto.scalarmult_base(in_sk.dest)))
        gc.collect()
        self.assrt(crypto.point_eq(crypto.decodepoint(src_entr.outputs[src_entr.real_output][1].mask),
                                   crypto.gen_c(in_sk.mask, src_entr.amount)))
        gc.collect()

        # RCT signature
        gc.collect()
        from apps.monero.xmr import mlsag2

        mg = None
        if self.use_simple_rct:
            # Simple RingCT
            mix_ring = []
            for idx2, out in enumerate(src_entr.outputs):
                mix_ring.append(out[1])

            mg, msc = mlsag2.prove_rct_mg_simple(self.full_message, mix_ring,
                                                 in_sk, alpha_c, pseudo_out_c, kLRki, None, index)

        else:
            # Full RingCt, only one input
            txn_fee_key = crypto.scalarmult_h(self.get_fee())
            n_total_outs = len(src_entr.outputs)
            mix_ring = [None] * n_total_outs
            for idx in range(n_total_outs):
                mix_ring[idx] = [src_entr.outputs[idx][1]]

            mg, msc = mlsag2.prove_rct_mg(self.full_message, mix_ring,
                                          [in_sk], self.output_sk, self.output_pk, kLRki, None, index, txn_fee_key)

        gc.collect()
        # Encode
        from apps.monero.xmr.sub.recode import recode_msg
        mgs = recode_msg([mg])
        cout = None

        gc.collect()
        # Multisig values returned encrypted, keys returned after finished successfully.
        if self.multi_sig:
            from apps.monero.xmr.enc import chacha_poly
            cout = chacha_poly.encrypt_pack(self.enc_key_cout(), crypto.encodeint(msc))

        # Final state transition
        if self.inp_idx + 1 == self.num_inputs():
            self.state.set_signature_done()
            await self.trezor.iface.transaction_signed()

        gc.collect()
        from trezor.messages.MoneroTsxSignInputResp import MoneroTsxSignInputResp
        return MoneroTsxSignInputResp(signature=await misc.dump_msg_gc(mgs[0], preallocate=488, del_msg=True), cout=cout)

    async def final_msg(self, *args, **kwargs):
        """
        Final step after transaction signing.

        :param args:
        :param kwargs:
        :return:
        """
        from trezor.messages.MoneroTsxFinalResp import MoneroTsxFinalResp
        from apps.monero.xmr.enc import chacha_poly

        self.state.set_final()

        cout_key = self.enc_key_cout() if self.multi_sig else None

        # Encrypted tx keys under transaction specific key, derived from txhash and spend key.
        # Deterministic transaction key, so we can recover it just from transaction and the spend key.
        tx_key, salt, rand_mult = misc.compute_tx_key(self.creds.spend_key_private, self.tx_prefix_hash)

        key_buff = crypto.encodeint(self.r) + b''.join([crypto.encodeint(x) for x in self.additional_tx_private_keys])
        tx_enc_keys = chacha_poly.encrypt_pack(tx_key, key_buff)

        return MoneroTsxFinalResp(cout_key=cout_key, salt=salt, rand_mult=rand_mult, tx_enc_keys=tx_enc_keys)
