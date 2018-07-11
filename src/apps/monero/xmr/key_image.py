#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

from apps.monero.xmr import common, crypto, ring_ct
from apps.monero.xmr.serialize.base_types import UVarintType
from apps.monero.xmr.serialize.int_serialize import dump_uvarint_b
from apps.monero.xmr.serialize.message_types import BlobType, ContainerType, MessageType
from apps.monero.xmr.serialize_messages.base import ECPublicKey, Hash


def compute_hash(rr):
    """
    Hash over output to ki-sync
    :param rr:
    :type rr: TransferDetails
    :return:
    """
    buff = b''
    buff += rr.out_key
    buff += rr.tx_pub_key
    if rr.additional_tx_pub_keys:
        buff += b''.join(rr.additional_tx_pub_keys)
    buff += dump_uvarint_b(rr.internal_output_index)

    return crypto.cn_fast_hash(buff)


async def export_key_image(creds, subaddresses, td):
    """
    Key image export
    :param creds:
    :param subaddresses:
    :param td:
    :return:
    """
    out_key = crypto.decodepoint(td.out_key)
    tx_pub_key = crypto.decodepoint(td.tx_pub_key)
    additional_tx_pub_keys = []
    if not common.is_empty(td.additional_tx_pub_keys):
        additional_tx_pub_keys = [crypto.decodepoint(x) for x in td.additional_tx_pub_keys]

    ki, sig = ring_ct.export_key_image(creds, subaddresses, out_key, tx_pub_key,
                                       additional_tx_pub_keys, td.internal_output_index)

    return ki, sig
