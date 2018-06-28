#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
XMR types
'''

from micropython import const
from . import xmrserialize as x
from .xmrserialize import eref


#
# cryptonote_basic.h
#


class Hash(x.BlobType):
    __slots__ = ['data']
    DATA_ATTR = 'data'
    FIX_SIZE = 1
    SIZE = 32


class ECKey(x.BlobType):
    __slots__ = ['bytes']
    DATA_ATTR = 'bytes'
    FIX_SIZE = 1
    SIZE = 32


class ECPoint(x.BlobType):
    __slots__ = ['data']
    DATA_ATTR = 'data'
    FIX_SIZE = 1
    SIZE = 32


class SecretKey(ECKey):
    __slots__ = ['bytes']


class ECPublicKey(ECPoint):
    __slots__ = ['data']


class KeyImage(ECPoint):
    __slots__ = ['data']


class KeyDerivation(ECPoint):
    __slots__ = ['data']


class UnorderedSet(x.ContainerType):
    pass


class TxoutToScript(x.MessageType):
    __slots__ = ['keys', 'script']
    VARIANT_CODE = 0x0
    MFIELDS = [
        ('keys', x.ContainerType, ECPublicKey),
        ('script', x.ContainerType, x.UInt8),
    ]


class TxoutToKey(x.MessageType):
    __slots__ = ['key']
    VARIANT_CODE = 0x2
    MFIELDS = [
        ('key', ECPublicKey),
    ]


class TxoutToScriptHash(x.MessageType):
    __slots__ = ['hash']
    VARIANT_CODE = 0x1
    MFIELDS = [
        ('hash', Hash),
    ]


class TxoutTargetV(x.VariantType):
    MFIELDS = [
        ('txout_to_script', TxoutToScript),
        ('txout_to_scripthash', TxoutToScriptHash),
        ('txout_to_key', TxoutToKey),
    ]


class TxinGen(x.MessageType):
    __slots__ = ['height']
    VARIANT_CODE = 0xff
    MFIELDS = [
        ('height', x.UVarintType),
    ]


class TxinToKey(x.MessageType):
    __slots__ = ['amount', 'key_offsets', 'k_image']
    VARIANT_CODE = 0x2
    MFIELDS = [
        ('amount', x.UVarintType),
        ('key_offsets', x.ContainerType, x.UVarintType),
        ('k_image', KeyImage),
    ]


class TxinToScript(x.MessageType):
    __slots__ = []
    VARIANT_CODE = 0x0
    MFIELDS = []


class TxinToScriptHash(x.MessageType):
    __slots__ = []
    VARIANT_CODE = 0x1
    MFIELDS = []


class TxInV(x.VariantType):
    MFIELDS = [
        ('txin_gen', TxinGen),
        ('txin_to_script', TxinToScript),
        ('txin_to_scripthash', TxinToScriptHash),
        ('txin_to_key', TxinToKey),
    ]


class TxOut(x.MessageType):
    __slots__ = ['amount', 'target']
    MFIELDS = [
        ('amount', x.UVarintType),
        ('target', TxoutTargetV),
    ]


class TransactionPrefix(x.MessageType):
    MFIELDS = [
        ('version', x.UVarintType),
        ('unlock_time', x.UVarintType),
        ('vin', x.ContainerType, TxInV),
        ('vout', x.ContainerType, TxOut),
        ('extra', x.ContainerType, x.UInt8),
    ]


class TransactionPrefixExtraBlob(TransactionPrefix):
    # noinspection PyTypeChecker
    MFIELDS = TransactionPrefix.MFIELDS[:-1] + [
        ('extra', x.BlobType),
    ]


#
# rctTypes.h
#


class Key64(x.ContainerType):
    FIX_SIZE = 1
    SIZE = 64
    ELEM_TYPE = ECKey


class KeyV(x.ContainerType):
    FIX_SIZE = 0
    ELEM_TYPE = ECKey


class KeyM(x.ContainerType):
    FIX_SIZE = 0
    ELEM_TYPE = KeyV


class KeyVFix(x.ContainerType):
    FIX_SIZE = 1
    ELEM_TYPE = ECKey


class KeyMFix(x.ContainerType):
    FIX_SIZE = 1
    ELEM_TYPE = KeyVFix


class CtKey(x.MessageType):
    __slots__ = ['dest', 'mask']
    MFIELDS = [
        ('dest', ECKey),
        ('mask', ECKey),
    ]


class CtkeyV(x.ContainerType):
    FIX_SIZE = 0
    ELEM_TYPE = CtKey


class CtkeyM(x.ContainerType):
    FIX_SIZE = 0
    ELEM_TYPE = CtkeyV


class MultisigKLRki(x.MessageType):
    MFIELDS = [
        ('K', ECKey),
        ('L', ECKey),
        ('R', ECKey),
        ('ki', ECKey),
    ]


class MultisigOut(x.MessageType):
    MFIELDS = [
        ('c', x.ContainerType, ECKey),
    ]


class EcdhTuple(x.MessageType):
    __slots__ = ['mask', 'amount']
    MFIELDS = [
        ('mask', ECKey),
        ('amount', ECKey),
    ]


class BoroSig(x.MessageType):
    __slots__ = ['s0', 's1', 'ee']
    MFIELDS = [
        ('s0', Key64),
        ('s1', Key64),
        ('ee', ECKey),
    ]


class MgSig(x.MessageType):
    __slots__ = ['ss', 'cc', 'II']
    MFIELDS = [
        ('ss', KeyM),
        ('cc', ECKey),
    ]


class RangeSig(x.MessageType):
    __slots__ = ['asig', 'Ci']
    MFIELDS = [
        ('asig', BoroSig),
        ('Ci', Key64),
    ]


class Bulletproof(x.MessageType):
    __slots__ = ['V', 'A', 'S', 'T1', 'T2', 'taux', 'mu', 'L', 'R', 'a', 'b', 't']
    MFIELDS = [
        ('A', ECKey),
        ('S', ECKey),
        ('T1', ECKey),
        ('T2', ECKey),
        ('taux', ECKey),
        ('mu', ECKey),
        ('L', KeyV),
        ('R', KeyV),
        ('a', ECKey),
        ('b', ECKey),
        ('t', ECKey),
    ]


class EcdhInfo(x.ContainerType):
    ELEM_TYPE = EcdhTuple


class RctSigBase(x.MessageType):
    __slots__ = ['type', 'txnFee', 'message', 'mixRing', 'pseudoOuts', 'ecdhInfo', 'outPk']
    MFIELDS = [
        ('type', x.UInt8),
        ('txnFee', x.UVarintType),
        ('message', ECKey),
        ('mixRing', CtkeyM),
        ('pseudoOuts', KeyV),
        ('ecdhInfo', EcdhInfo),
        ('outPk', CtkeyV),
    ]

    async def serialize_rctsig_base(self, ar, inputs, outputs):
        """
        Custom serialization
        :param ar:
        :type ar: x.Archive
        :return:
        """
        await self._msg_field(ar, idx=0)
        if self.type == RctType.Null:
            return
        if self.type != RctType.Full and self.type != RctType.FullBulletproof and \
                self.type != RctType.Simple and self.type != RctType.SimpleBulletproof:
            raise ValueError('Unknown type')

        await self._msg_field(ar, idx=1)
        if self.type == RctType.Simple:
            await ar.begin_array()
            await ar.prepare_container(inputs, eref(self, 'pseudoOuts'), KeyV)
            if ar.writing and len(self.pseudoOuts) != inputs:
                raise ValueError('pseudoOuts size mismatch')

            for i in range(inputs):
                await ar.field(eref(self.pseudoOuts, i), KeyV.ELEM_TYPE)
            await ar.end_array()

        await ar.begin_array()
        await ar.prepare_container(outputs, eref(self, 'ecdhInfo'), EcdhTuple)
        if ar.writing and len(self.ecdhInfo) != outputs:
            raise ValueError('EcdhInfo size mismatch')

        for i in range(outputs):
            await ar.field(eref(self.ecdhInfo, i), EcdhInfo.ELEM_TYPE)
        await ar.end_array()

        await ar.begin_array()
        await ar.prepare_container((outputs), eref(self, 'outPk'), CtKey)
        if ar.writing and len(self.outPk) != outputs:
            raise ValueError('outPk size mismatch')

        for i in range(outputs):
            await ar.field(eref(self.outPk[i], 'mask'), ECKey)
        await ar.end_array()


class RctType(object):
    Null = 0
    Full = 1
    Simple = 2
    FullBulletproof = 3
    SimpleBulletproof = 4


class RctSigPrunable(x.MessageType):
    __slots__ = ['rangeSigs', 'bulletproofs', 'MGs', 'pseudoOuts']
    MFIELDS = [
        ('rangeSigs', x.ContainerType, RangeSig),
        ('bulletproofs', x.ContainerType, Bulletproof),
        ('MGs', x.ContainerType, MgSig),
        ('pseudoOuts', KeyV),
    ]

    async def serialize_rctsig_prunable(self, ar, type, inputs, outputs, mixin):
        """
        Serialize rct sig
        :param ar:
        :type ar: x.Archive
        :param type:
        :param inputs:
        :param outputs:
        :param mixin:
        :return:
        """
        if type == RctType.Null:
            return True

        if type != RctType.Full and type != RctType.FullBulletproof and \
                type != RctType.Simple and type != RctType.SimpleBulletproof:
            raise ValueError('Unknown type')

        if type == RctType.SimpleBulletproof or type == RctType.FullBulletproof:
            await ar.begin_array()
            if len(self.bulletproofs) != outputs:
                raise ValueError('Bulletproofs size mismatch')

            await ar.prepare_container(outputs, eref(self, 'bulletproofs'), elem_type=Bulletproof)
            for i in range(len(self.bulletproofs)):
                await ar.field(elem=eref(self.bulletproofs, i), elem_type=Bulletproof)
            await ar.end_array()

        else:
            await ar.begin_array()
            await ar.prepare_container(outputs, eref(self, 'rangeSigs'), elem_type=RangeSig)
            if len(self.rangeSigs) != outputs:
                raise ValueError('rangeSigs size mismatch')

            for i in range(len(self.rangeSigs)):
                await ar.field(elem=eref(self.rangeSigs, i), elem_type=RangeSig)
            await ar.end_array()

        await ar.begin_array()

        # We keep a byte for size of MGs, because we don't know whether this is
        # a simple or full rct signature, and it's starting to annoy the hell out of me
        mg_elements = inputs if type == RctType.Simple or type == RctType.SimpleBulletproof else 1
        await ar.prepare_container(mg_elements, eref(self, 'MGs'), elem_type=MgSig)
        if len(self.MGs) != mg_elements:
            raise ValueError('MGs size mismatch')

        for i in range(mg_elements):
            # We save the MGs contents directly, because we want it to save its
            # arrays and matrices without the size prefixes, and the load can't
            # know what size to expect if it's not in the data
            await ar.begin_object()
            await ar.begin_array()

            await ar.prepare_container(mixin + 1, eref(self.MGs[i], 'ss'), elem_type=KeyM)
            if ar.writing and len(self.MGs[i].ss) != mixin + 1:
                raise ValueError('MGs size mismatch')

            for j in range(mixin + 1):
                await ar.begin_array()
                mg_ss2_elements = 1 + (1 if type == RctType.Simple or type == RctType.SimpleBulletproof else inputs)
                await ar.prepare_container(mg_ss2_elements, eref(self.MGs[i].ss, j), elem_type=KeyM.ELEM_TYPE)

                if ar.writing and len(self.MGs[i].ss[j]) != mg_ss2_elements:
                    raise ValueError('MGs size mismatch 2')

                for k in range(mg_ss2_elements):
                    await ar.field(eref(self.MGs[i].ss[j], k), elem_type=KeyV.ELEM_TYPE)
                await ar.end_array()

            await ar.field(eref(self.MGs[i], 'cc'), elem_type=ECKey)
            await ar.end_object()
        await ar.end_array()

        if type == RctType.SimpleBulletproof:
            await ar.begin_array()
            await ar.prepare_container(inputs, eref(self, 'pseudoOuts'), elem_type=KeyV)
            if ar.writing and len(self.pseudoOuts) != inputs:
                raise ValueError('pseudoOuts size mismatch')

            for i in range(inputs):
                await ar.field(eref(self.pseudoOuts, i), elem_type=KeyV.ELEM_TYPE)
            await ar.end_array()


class RctSig(RctSigBase):
    # noinspection PyTypeChecker
    MFIELDS = RctSigBase.MFIELDS + [
        ('p', RctSigPrunable),
    ]


class Signature(x.MessageType):
    __slots__ = ['c', 'r']
    MFIELDS = [
        ('c', ECKey),
        ('r', ECKey),
    ]

    async def serialize_archive(self, ar):
        ar.field(eref(self, 'c'), ECKey)
        ar.field(eref(self, 'r'), ECKey)
        return self


class SignatureArray(x.ContainerType):
    FIX_SIZE = 0
    ELEM_TYPE = Signature


def get_signature_size(msg):
    """
    Returns a signature size for the input
    :param msg:
    :return:
    """
    if isinstance(msg, (TxinGen, TxinToScript, TxinToScriptHash)):
        return 0
    elif isinstance(msg, TxinToKey):
        return len(msg.key_offsets)
    else:
        raise ValueError('Unknown tx in')


class Transaction(TransactionPrefix):
    # noinspection PyTypeChecker
    MFIELDS = TransactionPrefix.MFIELDS + [
        ('signatures', x.ContainerType, SignatureArray),
        ('rct_signatures', RctSig),
    ]

    async def serialize_archive(self, ar):
        """
        Serialize the transaction
        :param ar:
        :type ar: x.Archive
        :return:
        """
        # Transaction prefix serialization first.
        await ar.message(self, TransactionPrefix)

        if self.version == 1:
            await ar.begin_array()
            await ar.prepare_container(len(self.vin), eref(self, 'signatures'), elem_type=SignatureArray)
            signatures_not_expected = len(self.signatures) == 0
            if not signatures_not_expected and len(self.vin) != len(self.signatures):
                raise ValueError('Signature size mismatch')

            for i in range(len(self.vin)):
                sig_size = get_signature_size(self.vin[i])
                if signatures_not_expected:
                    if 0 == sig_size:
                        continue
                    else:
                        raise ValueError('Unexpected sig')

                await ar.prepare_container(sig_size, eref(self.signatures, i), elem_type=Signature)
                if sig_size != len(self.signatures[i]):
                    raise ValueError('Unexpected sig size')

                await ar.message(self.signatures[i], Signature)

        else:
            if len(self.vin) == 0:
                return

            await ar.begin_object()
            await ar.prepare_message(eref(self, 'rct_signatures'), RctSig)
            await self.rct_signatures.serialize_rctsig_base(ar, len(self.vin), len(self.vout))
            await ar.end_object()

            if self.rct_signatures.type != RctType.Null:
                mixin_size = len(self.vin[0].key_offsets) - 1 if len(self.vin) > 0 and isinstance(self.vin[0], TxinToKey) else 0
                await ar.begin_object()
                await ar.prepare_message(eref(self.rct_signatures, 'p'), RctSigPrunable)
                await self.rct_signatures.p.serialize_rctsig_prunable(ar, self.rct_signatures.type,
                                                                      len(self.vin), len(self.vout),
                                                                      mixin_size)
                await ar.end_object()
        return self


class AccountPublicAddress(x.MessageType):
    __slots__ = ['m_spend_public_key', 'm_view_public_key']
    MFIELDS = [
        ('m_spend_public_key', ECPublicKey),
        ('m_view_public_key', ECPublicKey),
    ]


class SubaddressIndex(x.MessageType):
    __slots__ = ['major', 'minor']
    MFIELDS = [
        ('major', x.UInt32),
        ('minor', x.UInt32),
    ]


class MultisigLR(x.MessageType):
    __slots__ = ['L', 'R']
    MFIELDS = [
        ('L', ECKey),
        ('R', ECKey),
    ]


class MultisigInfo(x.MessageType):
    __slots__ = ['signer', 'LR', 'partial_key_images']
    MFIELDS = [
        ('signer', ECPublicKey),
        ('LR', x.ContainerType, MultisigLR),
        ('partial_key_images', x.ContainerType, KeyImage),
    ]


class MultisigStruct(x.MessageType):
    __slots__ = ['sigs', 'ignore', 'used_L', 'signing_keys', 'msout']
    MFIELDS = [
        ('sigs', RctSig),
        ('ignore', ECPublicKey),
        ('used_L', x.ContainerType, ECKey),
        ('signing_keys', x.ContainerType, ECPublicKey),
        ('msout', MultisigOut),
    ]


class TxExtraPadding(x.MessageType):
    __slots__ = ['size']
    TX_EXTRA_PADDING_MAX_COUNT = 255

    VARIANT_CODE = 0x0
    MFIELDS = [
        ('size', x.SizeT),
    ]

    async def serialize_archive(self, ar):
        if ar.writing:
            if self.size > self.TX_EXTRA_PADDING_MAX_COUNT:
                raise ValueError('Padding too big')
            for i in range(self.size):
                ar.uint(0, x.UInt8)

        else:
            self.size = 0
            buffer = bytearray(1)
            for i in range(self.TX_EXTRA_PADDING_MAX_COUNT+1):
                self.size += 1
                try:
                    nread = await ar.iobj.areadinto(buffer)
                    if nread == 0:
                        break
                except EOFError:
                    break

                if buffer[0] != 0:
                    raise ValueError('Padding error')
        return self


class TxExtraPubKey(x.MessageType):
    __slots__ = ['pub_key']
    VARIANT_CODE = 0x1
    MFIELDS = [
        ('pub_key', ECPublicKey),
    ]


class TxExtraNonce(x.MessageType):
    __slots__ = ['nonce']
    VARIANT_CODE = 0x2
    MFIELDS = [
        ('nonce', x.BlobType),
    ]


class TxExtraMergeMiningTag(x.MessageType):
    VARIANT_CODE = 0x3
    MFIELDS = [
        ('field_len', x.UVarintType),
        ('depth', x.UVarintType),
        ('merkle_root', Hash),
    ]


class TxExtraAdditionalPubKeys(x.MessageType):
    __slots__ = ['data']
    VARIANT_CODE = 0x4
    MFIELDS = [
        ('data', x.ContainerType, ECPublicKey),
    ]


class TxExtraMysteriousMinergate(x.MessageType):
    __slots__ = ['data']
    VARIANT_CODE = 0xde
    MFIELDS = [
        ('data', x.BlobType),
    ]


class TxExtraField(x.VariantType):
    MFIELDS = [
        ('tx_extra_padding', TxExtraPadding),
        ('tx_extra_pub_key', TxExtraPubKey),
        ('tx_extra_nonce', TxExtraNonce),
        ('tx_extra_merge_mining_tag', TxExtraMergeMiningTag),
        ('tx_extra_additional_pub_keys', TxExtraAdditionalPubKeys),
        ('tx_extra_mysterious_minergate', TxExtraMysteriousMinergate),
    ]


class TxExtraFields(x.ContainerType):
    ELEM_TYPE = TxExtraField


class OutputEntry(x.TupleType):
    MFIELDS = [
        x.UVarintType, CtKey  # original: x.UInt64
    ]


class TxSourceEntry(x.MessageType):
    MFIELDS = [
        ('outputs', x.ContainerType, OutputEntry),
        ('real_output', x.SizeT),
        ('real_out_tx_key', ECPublicKey),
        ('real_out_additional_tx_keys', x.ContainerType, ECPublicKey),
        ('real_output_in_tx_index', x.UInt64),
        ('amount', x.UInt64),
        ('rct', x.BoolType),
        ('mask', ECKey),
        ('multisig_kLRki', MultisigKLRki),
    ]


class TxDestinationEntry(x.MessageType):
    __slots__ = ['amount', 'addr', 'is_subaddress']
    MFIELDS = [
        ('amount', x.UVarintType),  # original: UInt64
        ('addr', AccountPublicAddress),
        ('is_subaddress', x.BoolType),
    ]


class TransferDetails(x.MessageType):
    MFIELDS = [
        ('m_block_height', x.UInt64),
        ('m_tx', TransactionPrefix),
        ('m_txid', Hash),
        ('m_internal_output_index', x.SizeT),
        ('m_global_output_index', x.UInt64),
        ('m_spent', x.BoolType),
        ('m_spent_height', x.UInt64),
        ('m_key_image', KeyImage),
        ('m_mask', ECKey),
        ('m_amount', x.UInt64),
        ('m_rct', x.BoolType),
        ('m_key_image_known', x.BoolType),
        ('m_pk_index', x.SizeT),
        ('m_subaddr_index', SubaddressIndex),
        ('m_key_image_partial', x.BoolType),
        ('m_multisig_k', x.ContainerType, ECKey),
        ('m_multisig_info', x.ContainerType, MultisigInfo),
    ]


class TxConstructionData(x.MessageType):
    MFIELDS = [
        ('sources', x.ContainerType, TxSourceEntry),
        ('change_dts', TxDestinationEntry),
        ('splitted_dsts', x.ContainerType, TxDestinationEntry),
        ('selected_transfers', x.ContainerType, x.SizeT),
        ('extra', x.ContainerType, x.UInt8),
        ('unlock_time', x.UInt64),
        ('use_rct', x.BoolType),
        ('dests', x.ContainerType, TxDestinationEntry),
        ('subaddr_account', x.UInt32),
        ('subaddr_indices', x.ContainerType, x.UVarintType),  # original: x.UInt32
    ]


class PendingTransaction(x.MessageType):
    MFIELDS = [
        ('tx', Transaction),
        ('dust', x.UInt64),
        ('fee', x.UInt64),
        ('dust_added_to_fee', x.BoolType),
        ('change_dts', TxDestinationEntry),
        ('selected_transfers', x.ContainerType, x.SizeT),
        ('key_images', x.UnicodeType),
        ('tx_key', SecretKey),
        ('additional_tx_keys', x.ContainerType, SecretKey),
        ('dests', x.ContainerType, TxDestinationEntry),
        ('multisig_sigs', x.ContainerType, MultisigStruct),
        ('construction_data', TxConstructionData),
    ]


class PendingTransactionVector(x.ContainerType):
    ELEM_TYPE = PendingTransaction


class MultisigTxSet(x.MessageType):
    MFIELDS = [
        ('m_ptx', PendingTransactionVector),
        ('m_signers', UnorderedSet, ECPublicKey),
    ]






