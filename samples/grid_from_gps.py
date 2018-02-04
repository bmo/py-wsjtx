
# simple example to open a com port (using pyserial) to read NMEA sentences from an attached GPS,
# and supply the grid value to wsjtx.

# using standard NMEA sentences
import os
import sys
import threading
from datetime import datetime
import serial
import logging

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import pywsjtx
import pywsjtx.extra.simple_server
import pywsjtx.extra.latlong_to_grid_square

# Windows communications port we're using.
# TODO: gpsd on linux

COMPORT = 'COM8'
logging.basicConfig(level=logging.DEBUG)

class NMEALocation(object):
    # parse the NMEA message for location into a grid square

    def __init__(self, grid_changed_callback = None):
        self.valid = False
        self.grid = ""                  # this is an attribute, so allegedly doesn't need locking when used with multiple threads.
        self.last_fix_at = None
        self.grid_changed_callback = grid_changed_callback

    def handle_serial(self,text):
        # should be a single line.
        if text.startswith('$GPGLL'):
            logging.debug('nmea sentence: {}'.format(text.rstrip()))
            grid = pywsjtx.extra.latlong_to_grid_square.LatLongToGridSquare.GPGLL_to_grid(text)

            if grid != "":
                self.valid = True
                self.last_fix_at = datetime.utcnow()
            else:
                self.valid = False

            if  self.grid != grid:
                logging.debug("NMEALocation - grid mismatch old: {} new: {}".format(self.grid,grid))
                self.grid = grid
                if (self.grid_changed_callback):
                    c_thr = threading.Thread(target=self.grid_changed_callback, args=(grid,), kwargs={})
                    c_thr.start()

class SerialGPS(object):

    def __init__(self):
        self.line_handlers = []
        self.comm_thread = None
        self.comm_device = None
        self.stop_signalled = False

    def add_handler(self, line_handler):
        if (not (line_handler is None)) and (not (line_handler in self.line_handlers)):
            self.line_handlers.append(line_handler)

    def open(self, comport, baud, line_handler, **serial_kwargs):
        if self.comm_device is not None:
            self.close()
        self.stop_signalled = False
        self.comm_device = serial.Serial(comport, baud, **serial_kwargs)
        if self.comm_device is not None:
            self.add_handler(line_handler)
            self.comm_thread = threading.Thread(target=self.serial_worker, args=())
            self.comm_thread.start()

    def close(self):
        self.stop_signalled = True
        self.comm_thread.join()

        self.comm_device.close()
        self.line_handlers = []
        self.comm_device = None
        self.stop_signalled = False

    def remove_handler(self, line_handler):
        self.line_handlers.remove(line_handler)

    def serial_worker(self):
        while (True):
            if self.stop_signalled:
                return # terminate
            line = self.comm_device.readline()
            # dispatch the line
            # note that bytes are used for readline, vs strings after the decode to utf-8
            if line.startswith(b'$'):
                str_line = line.decode("utf-8")
                for p in self.line_handlers:
                    p(str_line)

    @classmethod
    def example_line_handler(cls, text):
        print('serial: ',text)

# set up the serial_gps to run
# get location data from the GPS, update the grid
# get the grid out of the status message from the WSJT-X instance

# if we have a grid, and it's not the same as GPS, then make it the same by sending the message.
# But only do that if triggered by a status message.


wsjtx_id = None
nmea_p = None
gps_grid = ""

def example_callback(new_grid):
    global gps_grid
    print("New Grid! {}".format(new_grid))
    # this sets the
    gps_grid = new_grid

sgps = SerialGPS()

s = pywsjtx.extra.simple_server.SimpleServer('224.1.1.1',5007)

print("Starting wsjt-x message server")

while True:

    (pkt, addr_port) = s.rx_packet()
    if (pkt != None):
        the_packet = pywsjtx.WSJTXPacketClassFactory.from_udp_packet(addr_port, pkt)
        if wsjtx_id is None and (type(the_packet) == pywsjtx.HeartBeatPacket):
            # we have an instance of WSJTX
            print("wsjtx detected, id is {}".format(the_packet.wsjtx_id))
            print("starting gps monitoring")
            wsjtx_id = the_packet.wsjtx_id
            # start up the GPS reader
            nmea_p = NMEALocation(example_callback)
            sgps.open(COMPORT, 9600, nmea_p.handle_serial, timeout=1.2)

        if type(the_packet) == pywsjtx.StatusPacket:
            if gps_grid != "" and the_packet.de_grid != gps_grid:
                print("Sending Grid Change to wsjtx-x, old grid:{} new grid: {}".format(the_packet.de_grid, gps_grid))
                grid_change_packet = pywsjtx.LocationChangePacket.Builder(wsjtx_id, "GRID:"+gps_grid)
                print(pywsjtx.PacketUtil.hexdump(grid_change_packet))
                s.send_packet(the_packet.addr_port, grid_change_packet)
                # for fun, change the TX5 message to our grid square, so we don't have to call CQ again
                # this only works if the length of the free text message is less than 13 characters.
                # if len(the_packet.de_call <= 5):
                #   free_text_packet = pywsjtx.FreeTextPacket.Builder(wsjtx_id,"73 {} {}".format(the_packet.de_call, the_packet[0:4]),False)
                #   s.send_packet(addr_port, free_text_packet)

        print(the_packet)



