#
#
#
#  Proof of concept -- colorize wsjt-x callsigns on the basis of dupe status in N1MM.
#
# Set up these variables:
# The N1MM Database file - this is a SQLite DB file that has an "s3db" file extension
N1MM_DB_FILE = "C:\\Users\\brian\\Documents\\N1MM Logger+\\Databases\\n9adg_2018.s3db"

# Download the CTY file from the same place that WL_CTY comes from. This is the country prefix lookup file.
CTY_FILE = "C:\\Users\\brian\\Documents\\N1MM Logger+\\SupportFiles\\CTY.DAT"
CONTESTNR = 1

# TODO: Find via Contest_name and START_DATE -- if multiple, show the CONTESTNR for all and have to use that strategy
#CONTEST_NAME="ARRLRTTY"
#START_DATE="2018-12-08 00:0:00"

TEST_MULTICAST = True

if TEST_MULTICAST:
    IP_ADDRESS = '224.1.1.1'
    PORT = 5007
else:
    IP_ADDRESS = '127.0.0.1'
    PORT = 2237

MY_MAX_SCHEMA = 3


import sqlite3
import os
import sys
import re
import queue
import threading
from datetime import datetime
import serial
import logging

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import pywsjtx
import pywsjtx.extra.simple_server

#
# TODO - listen for UDP packets from N1MM for logged QSOs to use as source of packets; process those and add to the queue, so colorization happens in somewhat realtime
# TODO - Interpret callsigns calling me <mycall> <theircall> to look up & colorize
#           K1ABC W9XYZ EN42
# TODO - Watch exchanges in general build table of callsigns and exchanges so we can find mults that way
#           K1ABC W9XYZ 579 IL
#           K1ABC W9XYZ R 559 IL
# ------------------- File picker instead of constant?
#import tkinter as tk
#from tkinter import filedialog

#root = tk.Tk()
#root.withdraw()

#file_path = filedialog.askopenfilename(title = "Select N1MM Database file to use",filetypes = (("N1MM Database File","*.s3db"),("all files","*.*")))

# -- TODO put these in separate files.
#--- N1MM-related
class N1MMLoggerPlus():
    database_path = None
    n1mm_sql_connection = None

    def __init__(self, n1mm_database_path, logger=None, **kwargs):
        self.verbose_logging = False
        self.logger = logger or logging.getLogger(__name__)
        self.database_path = n1mm_database_path
        #self.n1mm_sql_connection = self.open_n1mm_database(n1mm_database_path)
        logging.debug("n1mm database name {}".format(self.database_path))

    def open_db(self):
        if self.n1mm_sql_connection is not None:
            logging.error("Database is already open [{}]".format(self.db_file_name))
            raise Exception("Database is already open [{}]".format(self.db_file_name))

        cx = sqlite3.connect(self.database_path)
        cx.row_factory = sqlite3.Row
        self.n1mm_sql_connection = cx

    def close_db(self):
        if self.n1mm_sql_connection is not None:
            self.n1mm_sql_connection.close()
            self.database_path = None
            self.n1mm_sql_connection = None
        else:
            logging.info("close called, but connection not open.")

    def get_contest(self, **kwargs):
        contest_nr = kwargs.get("contestnr",None)
        if contest_nr is not None:
            c = self.n1mm_sql_connection.cursor()
            c.execute('SELECT * FROM ContestInstance where ContestID = ?', (contest_nr,))
            rows = c.fetchall()
            if len(rows) == 0:
                raise Exception("Cannot find ContestNR {} in N1MM Database".format(contest_nr))
            self.contestnr = contest_nr
            logging.debug("ContestNR {} found".format(contest_nr))
        else:
            pass

    def simple_dupe_status(self,callsign):
        if self.n1mm_sql_connection is None:
            raise Exception("N1MM database is not open")

        c = self.n1mm_sql_connection.cursor()
        c.execute('SELECT * FROM DXLOG where ContestNR = ? AND Call = ?', (self.contestnr, callsign,))
        rows = c.fetchall()
        logging.debug("dupe_status for {}: worked {} times".format(callsign, len(rows)))
        return len(rows)>0

    def prefix_worked_count(self, prefix):
        if self.n1mm_sql_connection is None:
            raise Exception("N1MM database is not open")

        c = self.n1mm_sql_connection.cursor()
        c.execute('SELECT COUNT(1) as C FROM DXLOG where ContestNR = ? AND CountryPrefix=?', (self.contestnr, prefix,))
        rows = c.fetchall()
        return rows[0]['C']

class Cty:
    cty_file_location = None
    table = {}
    def __init__(self, cty_file_location, **kwargs):
        # read the file
        self.logger = kwargs.get("logger",logging.getLogger(__name__))
        self.cty_file_location = cty_file_location

    def load(self):
        if os.path.isfile(self.cty_file_location)==False:
            raise Exception("CTY file [{}] doesn't exist".format(self.cty_file_location))
        fh = open(self.cty_file_location, 'r')

        while True:
            #   read lines

            first_line = fh.readline()
            if first_line is None or len(first_line)==0:
                break
            first_line = first_line.rstrip()
            fields = first_line.split(':')
            #logging.debug("Split into fields {}".format(fields))
            if len(fields) != 9:
                logging.warning("Wrong number of fields for line [{}] - {}".format(first_line, len(fields)))
                raise Exception("Can't parse CTY file - wrong number of fields on line {}".format(first_line))
            continent = fields[3].strip()
            primary_prefix = fields[7].strip()
            # now read the prefixes
            last_line = first_line
            prefix_lines = ""
            while not last_line.endswith(";"):
                last_line = fh.readline().rstrip()
                prefix_lines += last_line

            prefix_lines = prefix_lines.rstrip(";")

            prefix_or_callsign = prefix_lines.split(",")

            for p in prefix_or_callsign:
                p = p.strip()
                if p is None:
                    continue

                # handle special suffixes
                # The following special characters can be applied after an alias prefix:
                # (#)	Override CQ Zone
                # [#]	Override ITU Zone
                # <#/#>	Override latitude/longitude
                # {aa}	Override Continent
                # ~#~	Override local time offset from GMT
                p = re.sub(r'\{\d+\}', '', p)
                p = re.sub(r'\[\d+\]', '', p)
                p = re.sub(r'<\d+/\d+>', '', p)
                p = re.sub(r'\{\w\w\}', '', p)
                p = re.sub(r'~\d+~', '', p)
                exact_match = False
                #logging.debug("Adding prefix {} for {}".format(primary_prefix, p))
                self.table[p] = { 'primary_prefix' : primary_prefix, 'continent' : continent }

        fh.close()

    def prefix_for(self, callsign):
        # lookup the callsign in the CTY file data, return the prefix.
        prefixes = [k for k in self.table.keys() if k==callsign[0:len(k)] or k=="={}".format(callsign)]
        prefixes.sort(key = lambda s: 100-len(s))
        print("Prefixes {}".format(prefixes))
        found_prefix = None
        # exact matches first
        unique_call = [ c for c in prefixes if c.startswith('=')]
        if unique_call:
            if len(unique_call) > 1:
                logging.warning("More than one UNIQUE call matched: {}".format(unique_call))
            found_prefix = self.table[unique_call[0]]['primary_prefix']
            logging.debug("Prefix for {} is [{}] ({})".format(callsign,found_prefix,unique_call[0]))
            return found_prefix
        #
        if len(prefixes) > 0:
            k = prefixes[0]
            found_prefix = self.table[k]['primary_prefix']
            logging.debug("Prefix for {} is [{}] ({})".format(callsign, found_prefix, k))

        return found_prefix

class CallsignWorker:
    threads = []
    def __init__(self, threadcount, cty, n1mm_db_file_name, n1mm_args, **kwargs ):
        self.logger = kwargs.get("logger", logging.getLogger(__name__))
        self.input_queue = queue.Queue()
        self.output_queue = queue.Queue()
        self.threadcount = threadcount
        self.cty = cty

        self.n1mm_db_file_name = n1mm_db_file_name
        self.n1mm_args = n1mm_args

        self.threads = []
        self.internal_start_threads()

    def internal_start_threads(self):
        for i in range(self.threadcount):
            t = threading.Thread(target=self.callsign_lookup_worker)
            t.start()
            self.threads.append(t)

    def internal_stop_threads(self):
        for i in range(self.threadcount):
            self.input_queue.put(None)
        for t in self.threads:
            t.join()

    def stop_threads(self):
        self.internal_stop_threads()

    def callsign_lookup_worker(self):
        n1mm = N1MMLoggerPlus(self.n1mm_db_file_name,self.logger)
        n1mm.open_db()
        logging.warning(self.n1mm_args)
        n1mm.get_contest(**self.n1mm_args)

        while True:
            callsign = self.input_queue.get()
            if callsign is None:
                break
            prefix = self.cty.prefix_for(callsign)
            dupe_status = n1mm.simple_dupe_status(callsign)
            is_mult = not dupe_status and n1mm.prefix_worked_count(prefix)==0
            r = {
                    'callsign': callsign,
                    'dupe': dupe_status,
                    'is_mult': is_mult
            }
            logging.debug("Callsign status {}".format(r))
            self.output_queue.put(r)

def main():
    logFormatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s]  %(message)s")
    consoleFormatter = logging.Formatter('%(asctime)s %(message)s')
    logging.basicConfig(level=logging.INFO,format='%(asctime)s %(message)s')

    # set up file logging, as well
    fileHandler = logging.FileHandler("n1mm_arrl_ru_run.log")
    fileHandler.setFormatter(logFormatter)
    logging.getLogger().addHandler(fileHandler)
    # log to console
    if False:
        consoleHandler = logging.StreamHandler()
        consoleHandler.setFormatter(consoleFormatter)
        logging.getLogger().addHandler(consoleHandler)

    logging.getLogger().setLevel(logging.DEBUG)
    cty = Cty(CTY_FILE, logger=logging.getLogger())
    cty.load()

    n1mm = N1MMLoggerPlus(N1MM_DB_FILE,logger=logging.getLogger())
    n1mm.open_db()
    n1mm.get_contest(contestnr=CONTESTNR)

    # take calls that are CQing, or replying, etc. and colorize them after the dupe check

    cw = CallsignWorker(1, cty, N1MM_DB_FILE,{'contestnr':CONTESTNR})

    # get a callsign
    # put on queue

    s = pywsjtx.extra.simple_server.SimpleServer(IP_ADDRESS, PORT, timeout=2.0)
    mult_foreground_color =  pywsjtx.QCOLOR.Black()
    mult_background_color =  pywsjtx.QCOLOR.Red()

    dupe_background_color = pywsjtx.QCOLOR.RGBA(255,211,211,211) # light grey
    dupe_foreground_color = pywsjtx.QCOLOR.RGBA(255,169,169,169) # dark grey

    wsjtx_id = None
    while True:

        (pkt, addr_port) = s.rx_packet()
        if (pkt != None):
            the_packet = pywsjtx.WSJTXPacketClassFactory.from_udp_packet(addr_port, pkt)
            wsjtx_id = the_packet.wsjtx_id
            if type(the_packet) == pywsjtx.HeartBeatPacket:
                max_schema = max(the_packet.max_schema, MY_MAX_SCHEMA)
                reply_beat_packet = pywsjtx.HeartBeatPacket.Builder(the_packet.wsjtx_id, max_schema)
                s.send_packet(addr_port, reply_beat_packet)
            if type(the_packet) == pywsjtx.DecodePacket:
                m = re.match(r"^CQ\s+(\S{3,}?)\s+", the_packet.message) or re.match(r"^CQ\s+\S{2}\s+(\S{3,}?)\s+", the_packet.message)
                if m:
                    callsign = m.group(1)
                    print("Callsign {}".format(callsign))

                    cw.input_queue.put(callsign)
            print(the_packet)

        # service queue

        while not cw.output_queue.empty():
            resolved = cw.output_queue.get(False)
            print("Resolved packet available {}".format(resolved))
            if resolved['dupe']:
                color_pkt = pywsjtx.HighlightCallsignPacket.Builder(wsjtx_id, resolved['callsign'],
                                                                    dupe_background_color,
                                                                    dupe_foreground_color,
                                                                    True)
                s.send_packet(addr_port, color_pkt)
            if resolved['is_mult']:
                color_pkt = pywsjtx.HighlightCallsignPacket.Builder(wsjtx_id, resolved['callsign'],
                                                                    mult_background_color,
                                                                    mult_foreground_color,
                                                                    True)
                s.send_packet(addr_port, color_pkt)

            if not resolved['is_mult'] and not resolved['dupe']:
                color_pkt = pywsjtx.HighlightCallsignPacket.Builder(the_packet.wsjtx_id, callsign,
                                                        pywsjtx.QCOLOR.Uncolor(),
                                                        pywsjtx.QCOLOR.Uncolor(),
                                                        True)
                s.send_packet(addr_port, color_pkt)

if __name__ == "__main__":
        main()
