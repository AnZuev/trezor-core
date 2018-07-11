from apps.monero.controller import wrapper
from apps.common.display_address import show_qr, show_address
from trezor.messages.MoneroAddress import MoneroAddress


async def layout_monero_get_address(ctx, msg):
    address_n = msg.address_n or ()
    creds = await wrapper.monero_get_creds(ctx, address_n, msg.network_type)

    if msg.show_display:
        while True:
            if await show_address(ctx, creds.address.decode('ascii')):
                break
            if await show_qr(ctx, creds.address.decode('ascii')):
                break

    return MoneroAddress(address=creds.address)
