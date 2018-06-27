from trezor.wire import register, protobuf_workflow
from trezor.messages.wire_types import \
    MoneroGetAddress, MoneroGetWatchKey, MoneroTsxSign, MoneroKeyImageSync

# persistent state objects
from .sign_tx import layout_sign_tx
from .key_image_sync import layout_key_image_sync



def dispatch_MoneroGetAddress(*args, **kwargs):
    from .get_address import layout_monero_get_address
    return layout_monero_get_address(*args, **kwargs)


def dispatch_MoneroGetWatchKey(*args, **kwargs):
    from .get_watch_only import layout_monero_get_watch_only
    return layout_monero_get_watch_only(*args, **kwargs)


def dispatch_MoneroTsxSign(*args, **kwargs):
    return layout_sign_tx(*args, **kwargs)


def dispatch_MoneroKeyImageSync(*args, **kwargs):
    return layout_key_image_sync(*args, **kwargs)


def boot():
    register(MoneroGetAddress, protobuf_workflow, dispatch_MoneroGetAddress)
    register(MoneroGetWatchKey, protobuf_workflow, dispatch_MoneroGetWatchKey)
    register(MoneroTsxSign, protobuf_workflow, dispatch_MoneroTsxSign)
    register(MoneroKeyImageSync, protobuf_workflow, dispatch_MoneroKeyImageSync)
