
#sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import pywsjtx.extra.simple_server

s = pywsjtx.SimpleServer()

while True:
    (pkt, addr_port) = s.rx_packet()
    if (pkt != None):
        the_packet = pywsjtx.WSJTXPacketClassFactory.from_udp_packet(addr_port, pkt)
        if type(the_packet) == pywsjtx.StatusPacket:
            pass
        print(the_packet)


