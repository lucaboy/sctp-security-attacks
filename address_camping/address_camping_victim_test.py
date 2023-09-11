from scapy.all import sendp
from scapy.layers.inet import Ether, IP
from scapy.layers.sctp import SCTP, SCTPChunkInit, SCTPChunkParamIPv4Addr
from random import randint
from time import sleep

network_interface = "eth0"
src_address = "192.0.2.3"
multihoming_address = "192.0.2.4"
src_port = 40000
dst_address = "192.0.2.2"
dst_port = 38412

eth_ip = Ether() / IP(src=src_address, dst=dst_address)
sctp = SCTP(sport=src_port, dport=dst_port, tag=0x0)


def create_init_chunk() -> SCTPChunkInit:
    params = []
    params.append(SCTPChunkParamIPv4Addr(addr=multihoming_address))
    return SCTPChunkInit(
        init_tag=randint(1, pow(2, 32) - 1),
        a_rwnd=pow(2, 16) - 1,
        n_in_streams=10,
        n_out_streams=10,
        init_tsn=randint(0, pow(2, 32) - 1),
        params=params,
    )


chunk_init = create_init_chunk()

init_pkt = eth_ip / sctp / chunk_init

while True:
    sendp(init_pkt, iface=network_interface)
    sleep(5)
