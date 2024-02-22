import os
import sys
import sqlite3
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import pywsjtx.extra.simple_server

import re

TEST_MULTICAST = True
MATCH_MY_CALL = True  # use False to get packets for any call, useful for debugging

# N1MM database to check against
DBFILE = '/Users/brianmoran/Documents/T88WA/T88WA/COMBINED/t88wa_superset.s3db'

MYCALL = 'N9ADG'    # this will get updated from the status packets
dial_frequency = 14074000  # this will get updated from the status packets

# ContestNR column should NOT be equal to -1

if TEST_MULTICAST:
    IP_ADDRESS = '224.1.1.1'
    PORT = 5007
else:
    IP_ADDRESS = '127.0.0.1'
    PORT = 2237

MY_MAX_SCHEMA = 3

s = pywsjtx.extra.simple_server.SimpleServer(IP_ADDRESS, PORT, timeout=2.0)
def get_db():
    db = sqlite3.connect(DBFILE)
    return db

def lookup_dupe_status(callsign):
    db = get_db()
    c = db.cursor()
    c.execute("SELECT mode, band, count(*)  FROM DXLOG WHERE call = ? AND ContestNR <> -1 group by band, mode", (callsign,))
    return c.fetchall()

def calculate_dupe_score(current_band, all_records):
    score = 0
    for rec in all_records:
        mode, band, qcount = rec
        if (mode == 'FT8' and current_band == band):
            score += qcount * 2000
        elif (mode != 'FT8' and current_band == band):
            score += qcount * 300
        else:
            score += qcount * 20

    return score

def band_for(dial_frequency):
    band = 14.0
    if dial_frequency >= 1800000 and dial_frequency < 2000000:
        band = 1.8
    elif dial_frequency >= 3500000 and dial_frequency < 4000000:
        band = 3.5
    elif dial_frequency >= 5000000 and dial_frequency < 6000000:
        band = 5
    elif dial_frequency >= 7000000 and dial_frequency < 7500000:
        band = 7
    elif dial_frequency >= 10000000 and dial_frequency < 10500000:
        band = 10
    elif dial_frequency >= 14000000 and dial_frequency < 14400000:
        band = 14
    elif dial_frequency >= 18000000 and dial_frequency < 19000000:
        band = 18
    elif dial_frequency >= 21000000 and dial_frequency < 21600000:
        band = 21
    elif dial_frequency >= 24000000 and dial_frequency < 25000000:
        band = 24
    elif dial_frequency >= 28000000 and dial_frequency < 30000000:
        band = 28
    elif dial_frequency >= 50000000 and dial_frequency < 55000000:
        band = 50
    elif dial_frequency >= 144000000 and dial_frequency < 148000000:
        band = 144

    return band
test_data = [('FT8', 7.0, 1), ('CW', 10.0, 1), ('FT8', 14.0, 1), ('FT8', 18.0, 1), ('FT8', 28.0, 1)]
test_band = 7.0
print("Dupe score for data {} {}".format(test_band, calculate_dupe_score(test_band, test_data)))
#exit(0);
while True:
    (pkt, addr_port) = s.rx_packet()
    if addr_port is None:
        print(".")
        continue
    #print("Packet from {}".format(addr_port))
    if (pkt != None):
        the_packet = pywsjtx.WSJTXPacketClassFactory.from_udp_packet(addr_port, pkt)
        print(the_packet)

        if type(the_packet) == pywsjtx.StatusPacket:
            dial_frequency = the_packet.dial_frequency
            MYCALL = the_packet.de_call
            if MYCALL.find('/') >= 0:
                MYCALL = '<' + MYCALL + '>'

        if type(the_packet) == pywsjtx.HeartBeatPacket:
            max_schema = max(the_packet.max_schema, MY_MAX_SCHEMA)
            reply_beat_packet = pywsjtx.HeartBeatPacket.Builder(the_packet.wsjtx_id,max_schema)
            s.send_packet(addr_port, reply_beat_packet)

        if type(the_packet) == pywsjtx.DecodePacket:
            if the_packet.message is None:
                print("No messages in packet!!!!")
                continue
            # get the callsigns calling
            if MATCH_MY_CALL:
                m = re.match(re.compile("^({mycall})\s+(\S+)\s+".format(mycall = MYCALL)), the_packet.message)
            else:
                m = re.match(r"^(\S+)\s+(\S+)\s+", the_packet.message)
            if m:
                callsign = m.group(2)
                #print(lookup_dupe_status(callsign))
                dupe_tuples = lookup_dupe_status(callsign)
                dupe_score = calculate_dupe_score(band_for(dial_frequency), dupe_tuples)
                # I just like saying "dupe tuple" in my head
                print("{} Dupe Score on {} is {} - {}\n".format(callsign, band_for(dial_frequency), dupe_score, dupe_tuples))

                if dupe_score > 2000:
                    color_pkt = pywsjtx.HighlightCallsignPacket.Builder(the_packet.wsjtx_id, callsign,

                                                                   pywsjtx.QCOLOR.Red(),
                                                                   pywsjtx.QCOLOR.White(),  # RGBA(255, 50, 137, 48 ),
                                                                   False)
                    s.send_packet(addr_port, color_pkt)

                if dupe_score > 0:
                    annotate_pkt = pywsjtx.AnnotateCallsignPacket.Builder(the_packet.wsjtx_id
                                                                      , callsign
                                                                      , True
                                                                      , dupe_score)
                    s.send_packet(addr_port, annotate_pkt)



