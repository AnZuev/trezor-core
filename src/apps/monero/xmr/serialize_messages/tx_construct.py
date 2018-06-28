from apps.monero.xmr.serialize.base_types import BoolType, UVarintType, SizeT, UInt64, UInt8, UInt32
from apps.monero.xmr.serialize.message_types import MessageType, ContainerType, UnicodeType
from apps.monero.xmr.serialize_messages.addr import SubaddressIndex
from apps.monero.xmr.serialize_messages.base import ECKey, ECPublicKey, KeyImage, Hash, SecretKey, UnorderedSet
from apps.monero.xmr.serialize_messages.tx_dest_entry import TxDestinationEntry
from apps.monero.xmr.serialize_messages.tx_full import RctSig, Transaction
from apps.monero.xmr.serialize_messages.tx_prefix import TransactionPrefix
from apps.monero.xmr.serialize_messages.tx_src_entry import TxSourceEntry


class MultisigOut(MessageType):
    MFIELDS = [
        ('c', ContainerType, ECKey),
    ]


class MultisigLR(MessageType):
    __slots__ = ['L', 'R']
    MFIELDS = [
        ('L', ECKey),
        ('R', ECKey),
    ]


class MultisigInfo(MessageType):
    __slots__ = ['signer', 'LR', 'partial_key_images']
    MFIELDS = [
        ('signer', ECPublicKey),
        ('LR', ContainerType, MultisigLR),
        ('partial_key_images', ContainerType, KeyImage),
    ]


class MultisigStruct(MessageType):
    __slots__ = ['sigs', 'ignore', 'used_L', 'signing_keys', 'msout']
    MFIELDS = [
        ('sigs', RctSig),
        ('ignore', ECPublicKey),
        ('used_L', ContainerType, ECKey),
        ('signing_keys', ContainerType, ECPublicKey),
        ('msout', MultisigOut),
    ]


class TransferDetails(MessageType):
    MFIELDS = [
        ('m_block_height', UInt64),
        ('m_tx', TransactionPrefix),
        ('m_txid', Hash),
        ('m_internal_output_index', SizeT),
        ('m_global_output_index', UInt64),
        ('m_spent', BoolType),
        ('m_spent_height', UInt64),
        ('m_key_image', KeyImage),
        ('m_mask', ECKey),
        ('m_amount', UInt64),
        ('m_rct', BoolType),
        ('m_key_image_known', BoolType),
        ('m_pk_index', SizeT),
        ('m_subaddr_index', SubaddressIndex),
        ('m_key_image_partial', BoolType),
        ('m_multisig_k', ContainerType, ECKey),
        ('m_multisig_info', ContainerType, MultisigInfo),
    ]


class TxConstructionData(MessageType):
    MFIELDS = [
        ('sources', ContainerType, TxSourceEntry),
        ('change_dts', TxDestinationEntry),
        ('splitted_dsts', ContainerType, TxDestinationEntry),
        ('selected_transfers', ContainerType, SizeT),
        ('extra', ContainerType, UInt8),
        ('unlock_time', UInt64),
        ('use_rct', BoolType),
        ('dests', ContainerType, TxDestinationEntry),
        ('subaddr_account', UInt32),
        ('subaddr_indices', ContainerType, UVarintType),  # original: x.UInt32
    ]


class PendingTransaction(MessageType):
    MFIELDS = [
        ('tx', Transaction),
        ('dust', UInt64),
        ('fee', UInt64),
        ('dust_added_to_fee', BoolType),
        ('change_dts', TxDestinationEntry),
        ('selected_transfers', ContainerType, SizeT),
        ('key_images', UnicodeType),
        ('tx_key', SecretKey),
        ('additional_tx_keys', ContainerType, SecretKey),
        ('dests', ContainerType, TxDestinationEntry),
        ('multisig_sigs', ContainerType, MultisigStruct),
        ('construction_data', TxConstructionData),
    ]


class PendingTransactionVector(ContainerType):
    ELEM_TYPE = PendingTransaction


class MultisigTxSet(MessageType):
    MFIELDS = [
        ('m_ptx', PendingTransactionVector),
        ('m_signers', UnorderedSet, ECPublicKey),
    ]
