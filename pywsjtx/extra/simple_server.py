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
import ipaddress

class SimpleServer(object):
    logger = logging.getLogger()
    MAX_BUFFER_SIZE = pywsjtx.GenericWSJTXPacket.MAXIMUM_NETWORK_MESSAGE_SIZE
    DEFAULT_UDP_PORT = 2237
    #
    #
    def __init__(self, ip_address='127.0.0.1', udp_port=DEFAULT_UDP_PORT, **kwargs):
        self.timeout = None
        self.verbose = kwargs.get("verbose",False)
        self.interface = kwargs.get("interface", "127.0.0.1")

        if kwargs.get("timeout") is not None:
            self.timeout = kwargs.get("timeout")

        the_address = ipaddress.ip_address(ip_address)
        if not the_address.is_multicast:
            self.sock = socket.socket(socket.AF_INET,  # Internet
                                 socket.SOCK_DGRAM)  # UDP

            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.sock.bind((ip_address, int(udp_port)))
        else:
            self.multicast_setup(ip_address, udp_port, self.interface)

        if self.timeout is not None:
            self.sock.settimeout(self.timeout)

    def multicast_setup(self, group, port='', interface='127.0.0.1'):
        print("Multicast setup addr %s port %s interface %s" % (group, port, interface))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP
                             , socket.inet_aton(group) + socket.inet_aton(interface))
        self.sock.bind(('', port))
        # TODO in the future be able to handle more than one address?
        #mreq = struct.pack("4s4s", socket.inet_aton(group), socket.inet_aton(interface)) # INADDR_ANY)
        #self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    def rx_packet(self):
        try:
            pkt, addr_port = self.sock.recvfrom(self.MAX_BUFFER_SIZE)  # buffer size is 1024 bytes
            return(pkt, addr_port)
        except socket.timeout:
            if self.verbose:
                logging.debug("rx_packet: socket.timeout")
            return (None, None)

    def send_packet(self, addr_port, pkt):
        bytes_sent = self.sock.sendto(pkt,addr_port)
        self.logger.debug("send_packet: Bytes sent {} ".format(bytes_sent))

    def demo_run(self):
        while True:
            (pkt, addr_port) = self.rx_packet()
            if (pkt != None):
                the_packet = pywsjtx.WSJTXPacketClassFactory.from_udp_packet(addr_port, pkt)
                print(the_packet)
