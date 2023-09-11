from scapy.all import srp1
from scapy.layers.inet import Ether, IP
from scapy.layers.sctp import (
    SCTP,
    SCTPChunkInit,
    SCTPChunkCookieEcho,
    SCTPChunkParamStateCookie,
)
from random import randint

network_interface = "eth0"
src_address = "192.0.2.1"
src_port = 40000
dst_address = "192.0.2.2"
dst_port = 38412

eth_ip = Ether() / IP(src=src_address, dst=dst_address)


def create_init_chunk() -> SCTPChunkInit:
    return SCTPChunkInit(
        init_tag=randint(1, pow(2, 32) - 1),
        a_rwnd=pow(2, 16) - 1,
        n_in_streams=10,
        n_out_streams=10,
        init_tsn=randint(0, pow(2, 32) - 1),
    )


init_chunk = create_init_chunk()


def init_association(src_port, dst_port):
    sctp = SCTP(sport=src_port, dport=dst_port, tag=0x0)
    init_pkt = eth_ip / sctp / init_chunk

    init_ack_pkt = srp1(init_pkt, iface=network_interface)
    init_ack_chunk = init_ack_pkt.lastlayer()
    init_ack_chunk_params = init_ack_chunk.fields.get("params")

    verification_tag = init_ack_chunk.fields.get("init_tag")
    cookie = SCTPChunkParamStateCookie(bytes(init_ack_chunk_params[0])).cookie
    sctp.fields["sport"] = src_port + 1
    sctp.fields["tag"] = verification_tag
    chunk_cookie_echo = SCTPChunkCookieEcho(cookie=cookie)
    cookie_echo_pkt = eth_ip / sctp / chunk_cookie_echo

    cookie_ack_pkt = srp1(cookie_echo_pkt, iface=network_interface)
    cookie_ack_pkt.show2()


init_association(src_port, dst_port)