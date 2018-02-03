#
# In WSJTX parlance, the 'network server' is a program external to the wsjtx.exe program that handles packets emitted by wsjtx
#
# TODO: handle multicast groups.
#
# see dump_wsjtx_packets.py example for some simple usage
#
import socket
import struct
import pywsjtx
import logging

class SimpleServer(object):
    logger = logging.getLogger()
    MAX_BUFFER_SIZE = pywsjtx.GenericWSJTXPacket.MAXIMUM_NETWORK_MESSAGE_SIZE
    DEFAULT_UDP_PORT = 2237
    #
    # note that '' and '127.0.0.1' behave differently. On Windows, try '' instead of 127.0.0.1 if you're not receiving any packets.
    #
    def __init__(self, ip_address='', udp_port=DEFAULT_UDP_PORT, **kwargs):
        self.timeout = None

        if kwargs.get("timeout") is not None:
            self.timeout = kwargs.get("timeout")

        self.sock = socket.socket(socket.AF_INET,  # Internet
                             socket.SOCK_DGRAM)  # UDP

        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        if self.timeout is not None:
            self.sock.settimeout(self.timeout)

        self.sock.bind((ip_address, int(udp_port)))

    # can through a sock.timeout exception if it's configured that way.
    def rx_packet(self):
        pkt, addr_port = self.sock.recvfrom(self.MAX_BUFFER_SIZE)  # buffer size is 1024 bytes
        return(pkt, addr_port)

    def send_packet(self, addr_port, pkt):
        bytes_sent = self.sock.sendto(pkt,addr_port)
        self.logger.debug("send_packet: Bytes sent ",bytes_sent)

    def demo_run(self):
        while True:
            (pkt, addr_port) = self.rx_packet()
            if (pkt != None):
                the_packet = pywsjtx.WSJTXPacketClassFactory.from_udp_packet(addr_port, pkt)
                print(the_packet)
