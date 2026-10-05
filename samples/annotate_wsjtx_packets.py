import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import pywsjtx.extra.simple_server

import re
import random

TEST_MULTICAST = True
MYCALL = 'TO4A'
if TEST_MULTICAST:
    IP_ADDRESS = '224.1.1.1'
    PORT = 5007
else:
    IP_ADDRESS = '127.0.0.1'
    PORT = 2237

MY_MAX_SCHEMA = 3

s = pywsjtx.extra.simple_server.SimpleServer(IP_ADDRESS, PORT, timeout=2.0)

while True:

    (pkt, addr_port) = s.rx_packet()
    print("Packet from {}".format(addr_port))
    if (pkt != None):
        the_packet = pywsjtx.WSJTXPacketClassFactory.from_udp_packet(addr_port, pkt)

        if type(the_packet) == pywsjtx.HeartBeatPacket:
            max_schema = max(the_packet.max_schema, MY_MAX_SCHEMA)
            reply_beat_packet = pywsjtx.HeartBeatPacket.Builder(the_packet.wsjtx_id,max_schema)
            s.send_packet(addr_port, reply_beat_packet)
        if type(the_packet) == pywsjtx.DecodePacket:
            m = re.match(r"^CQ\s+(\S+)\s+", the_packet.message)
            if False and m:
                print("Callsign {}".format(m.group(1)))
                callsign = m.group(1)

                color_pkt = pywsjtx.HighlightCallsignPacket.Builder(the_packet.wsjtx_id, callsign,

                                                                    pywsjtx.QCOLOR.White(),
                                                                    pywsjtx.QCOLOR.Red(),
                                                                    True)

                normal_pkt = pywsjtx.HighlightCallsignPacket.Builder(the_packet.wsjtx_id, callsign,
                                                                    pywsjtx.QCOLOR.Uncolor(),
                                                                    pywsjtx.QCOLOR.Uncolor(),
                                                                    True)
                s.send_packet(addr_port, color_pkt)
                #print(pywsjtx.PacketUtil.hexdump(color_pkt))

            m = re.match(re.compile("^({mycall})\s+(\S+)\s+".format(mycall = MYCALL)), the_packet.message)
            if m:
                print("********************************  CALLER {}".format(m.group(2)))
                callsign = m.group(2)

                color_pkt = pywsjtx.HighlightCallsignPacket.Builder(the_packet.wsjtx_id, callsign,

                                                                    pywsjtx.QCOLOR.Red(),
                                                                    pywsjtx.QCOLOR.White(), # RGBA(255, 50, 137, 48 ),
                                                                    False)

                normal_pkt = pywsjtx.HighlightCallsignPacket.Builder(the_packet.wsjtx_id, callsign,
                                                                     pywsjtx.QCOLOR.Uncolor(),
                                                                     pywsjtx.QCOLOR.Uncolor(),
                                                                     False)
                annotate_pkt = pywsjtx.AnnotateCallsignPacket.Builder(the_packet.wsjtx_id, "UA0LBF",
                                                              True,
                                                              12);
                annotate_pkt2 = pywsjtx.AnnotateCallsignPacket.Builder(the_packet.wsjtx_id, "HL3AMO",
                                                                      True,
                                                                      67);
                if True:
                    s.send_packet(addr_port, color_pkt)
                    s.send_packet(addr_port, annotate_pkt)
                    s.send_packet(addr_port, annotate_pkt2)
                else:
                    s.send_packet(addr_port, normal_pkt)
        print(the_packet)


