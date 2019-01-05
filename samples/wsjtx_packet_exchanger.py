#
# A rude work around to get JTAlert v.2, N1MM Logger+ 1.0.7422.0 (first version with WSJTX support), and WSJT-X 2.0 working
# together.
#
# 0. Start this program (python 3.x)
# 1. Start wsjt-x. Configure UDP server port to be 224.1.1.1, port 5007
# 2. Start N1MM. No configuration possible for wsjtx window
# 3. Verify that N1MM's wsjtx window is receiving CQ spots from wsjtx
# 4. Edit the file C:\Users\<YOURUSERNAME>\AppData\Local\WSJT-X\WSJT-X.ini
#     add these two lines above the UDPServer=224.1.1.1 line:
#        udpserver=127.0.0.1
#         udpserverport=2238
#     Put a comment in front of the UDPServer= and UDPServerPort= lines, like this:
#           #UDPServer=224.0.0.1
#           #UDPServerPort=5007
# 5. Save the file.
# 6.   Start JT-Alert (JTAlert will read the .ini file with the 127.0.0.1:2238 values, and start receiving packets
# 7. Comment out the 127.0.0.1:2238 UDPServer lines with #
# 8. Save the file again.

#  You'll have to do this again each time you start up JTAlert to 'fool' it into using port 2238.
#
# Issues: JTALERT-X closes it's socket connection while the settings dialog is open. We do the brute force thing of trying to
# reestablish the connection to the port


# WSJT-X talks to a multicast port. This program sits on the multicast port, and forwards packets it receives to other Unicast sockets.
# It also listens on the unicast sockets, and forwards received packets back to WSJT-X.

# It assumes that there's only ONE other application sending packets to the multicast socket (WSJT-X)
#

MULTICAST_PORT = { 'ip_address':'224.1.1.1', 'port':5007, 'timeout':0.2 }
FORWARDING_PORTS = [
    { 'ip_address': '127.0.0.1', 'port': 2237, 'timeout':0.2 },
    { 'ip_address': '127.0.0.1', 'port': 2238, 'timeout':0.2 }
]

import os
import sys
import logging

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import pywsjtx
import pywsjtx.extra.simple_server

#
# The RIGHT way to do a packet redistributor like this is to select or wait on the sockets.
# This one trades a little latency (~.50 seconds for two unicast and one multicast socket) for
# not changing some other code I had around
#
def main():
    logFormatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s]  %(message)s")
    consoleFormatter = logging.Formatter('%(asctime)s %(message)s')
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(message)s')
    wsjtx_instance_addr_port = None
    servers = []
    master_server =  pywsjtx.extra.simple_server.SimpleServer(MULTICAST_PORT['ip_address'], MULTICAST_PORT['port'],
                                                              timeout=MULTICAST_PORT['timeout'])
    for port_spec in FORWARDING_PORTS:
        servers.append({"instance":pywsjtx.extra.simple_server.SimpleServer(port_spec.get('server_ip_address','127.0.0.1'),
                                                                           port_spec.get('server_port',0), timeout=port_spec['timeout']),
                        "to_addr_port": (port_spec['ip_address'], port_spec['port']),
                        "server_spec": port_spec })

    while (True):
        pkt, wsjtx_instance_addr_port = master_server.rx_packet()
        if pkt is not None:
            logging.debug('RX packet from wsjtx')
            for s in servers:
                s['instance'].send_packet(s['to_addr_port'],pkt )
            for s in servers:
                try:
                    pkt, srv_instance_addr_port = s['instance'].rx_packet()
                    if pkt is not None:
                        logging.debug('RX packet from {}'.format(s['to_addr_port']))
                        master_server.send_packet(wsjtx_instance_addr_port,pkt)
                except ConnectionResetError:
                    # reopen the port.
                    logging.debug("ERROR - Restarting port {}".format(s['to_addr_port']))
                    s["instance"] = pywsjtx.extra.simple_server.SimpleServer(port_spec.get('server_ip_address','127.0.0.1'),
                                                                           port_spec.get('server_port',0), timeout=port_spec['timeout'])


if __name__ == "__main__":
        main()
