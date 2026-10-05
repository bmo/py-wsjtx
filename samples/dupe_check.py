#
# dupe_check.py - colors callsigns in WSJT-X that are already in your N1MM Logger+ log.
#
# For each callsign WSJT-X decodes, this looks it up in N1MM's log and scores how "worked" it is: QSOs on the
# current band in FT8 count most, other modes on this band less, other bands least. WSJT-X then shows callsigns
# already worked in FT8 on this band in red, and sorts the rest by score.
#
# Settings are in dupe_check.cfg (copy dupe_check.cfg.example). With no settings it follows N1MM: it reads N1MM's
# current database from "N1MM Logger.ini" and checks every log in it.
#
#   python dupe_check.py                   run with dupe_check.cfg (or the defaults)
#   python dupe_check.py --pick            choose the database and log from a list
#   python dupe_check.py --pick --save-config    ...and remember the choice in dupe_check.cfg
#   python dupe_check.py -c other.cfg -v   another config file; -v prints every WSJT-X message
#
import argparse
import configparser
import ipaddress
import os
import re
import socket
import sqlite3
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import pywsjtx.extra.simple_server
import n1mm_logs

DEFAULT_CONFIG = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dupe_check.cfg')

MY_MAX_SCHEMA = 3
SILENCE_WARNING = 30       # seconds without a message from WSJT-X before saying so

DEFAULTS = {
    'n1mm': {
        'database': '',            # blank: the database N1MM has open (from its ini file)
        'contest_nr': 'all',       # all: every log in the database; current: the log N1MM has open; or a log number
        'ini': '',                 # blank: Documents\N1MM Logger+\N1MM Logger.ini
    },
    'wsjtx': {
        'address': '224.1.1.1',    # WSJT-X's UDP Server address (Settings > Reporting); multicast lets other programs share it
        'port': '2237',
        'interface': '127.0.0.1',  # for multicast: the network interface to listen on; blank for any
    },
    'dupe_check': {
        'match_my_call': 'true',   # true: only look up stations calling you; false: every decoded message
        'include_ft4': 'false',    # true: earlier FT4 QSOs count like FT8 ones; false: FT4 counts as another mode
        'verbose': 'false',        # true: print every WSJT-X message
        'show_lookups': 'true',    # true: print every callsign as it's looked up; false: only ones already worked
    },
}


def load_config(path):
    config = configparser.RawConfigParser(inline_comment_prefixes=('#', ';'))
    config.read_dict(DEFAULTS)
    if os.path.exists(path):
        config.read(path)
    return config


class DupeDatabase(object):
    """ Looks up callsigns in an N1MM database over one read-only connection, opened once and reused. """

    def __init__(self, path, contest_nr=None):
        self.path = path
        self.contest_nr = contest_nr   # None: all logs
        self.db = None

    def connect(self):
        if self.db is None:
            self.db = n1mm_logs.open_readonly(self.path)
        return self.db

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None

    def lookup(self, callsign):
        """ [(mode, band, count), ...] of earlier QSOs with this callsign (deleted QSOs, in log -1, don't count). """
        sql = "SELECT mode, band, count(*) FROM DXLOG WHERE call = ? AND ContestNR <> -1"
        params = (callsign,)
        if self.contest_nr is not None:
            sql += " AND ContestNR = ?"
            params += (self.contest_nr,)
        sql += " GROUP BY band, mode"
        try:
            return self.connect().execute(sql, params).fetchall()
        except sqlite3.Error:
            # e.g. the file was replaced or briefly unavailable: start a fresh connection and try once more
            self.close()
            return self.connect().execute(sql, params).fetchall()


def calculate_dupe_score(current_band, all_records, same_modes=('FT8',)):
    """ same_modes: the modes whose QSOs on this band count most (FT8, and optionally FT4). """
    score = 0
    for rec in all_records:
        mode, band, qcount = rec
        if (mode in same_modes and current_band == band):
            score += qcount * 2000
        elif (mode not in same_modes and current_band == band):
            score += qcount * 300
        else:
            score += qcount * 20

    return score


def band_for(dial_frequency):
    band = 14.0  # a frequency outside the bands below counts as 20m
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


def looks_like_call(word):
    """ Callsigns have at least one letter and one digit; CQ modifiers (DX, NA, POTA, TEST) and reports don't. """
    word = word.strip('<>').upper()
    return (2 < len(word) <= 13 and re.fullmatch(r'[A-Z0-9/]+', word) is not None
            and re.search(r'[A-Z]', word) is not None and re.search(r'[0-9]', word) is not None)


def caller_in(message, my_call=None):
    """ The callsign of the station transmitting a decoded message, or None.
            "N9ADG K1ABC -12"  -> K1ABC      (a station calling N9ADG: the sender comes second)
            "CQ DX K1ABC FN42" -> K1ABC      (a CQ, perhaps with a modifier: the first callsign after it)
        With my_call, only messages addressed to my_call count. WSJT-X's <angle brackets> are removed. """
    words = message.split()
    if len(words) < 2:
        return None
    first = words[0].strip('<>').upper()
    if my_call is not None:
        if first != my_call.strip('<>').upper():
            return None
        caller = words[1]
    elif first in ('CQ', 'QRZ'):
        caller = next((w for w in words[1:] if looks_like_call(w)), None)
    else:
        caller = words[1]
    if caller is None or not looks_like_call(caller):
        return None
    return caller.strip('<>').upper()


def lookup_line(callsign, band, score, records):
    """ One line for a lookup: "19:56:30Z  YT0A        14 MHz  score    600  JTTY 14 MHz x2" """
    if records:
        found = "score {score:>6}  {qsos}".format(score=score, qsos=', '.join(
            "{mode} {band:g} MHz x{n}".format(mode=mode, band=float(b), n=n) for mode, b, n in records))
    else:
        found = "not in log"
    return "{t}Z  {call:<10}  {band:>3g} MHz  {found}".format(
        t=time.strftime('%H:%M:%S', time.gmtime()), call=callsign, band=float(band), found=found)


def choose_log(config, config_path, pick):
    """ Which database and log to check: (database path, contest nr or None for all logs, description). """
    ini = config.get('n1mm', 'ini') or n1mm_logs.default_ini_path()
    current = n1mm_logs.current_log(ini)
    database = config.get('n1mm', 'database').strip()

    # nothing says which database: if someone's at the keyboard, ask
    if not pick and not database and not current and n1mm_logs.keyboard_attached():
        print("No database set in [n1mm] database, and N1MM's current database isn't in {ini}.".format(ini=ini))
        pick = True

    if pick:
        folders = [n1mm_logs.default_database_folder()]
        if config.get('n1mm', 'database'):
            folders.insert(0, os.path.dirname(os.path.abspath(config.get('n1mm', 'database'))))
        databases = ([current[0]] if current else []) + n1mm_logs.find_databases(folders)
        databases = [p for i, p in enumerate(databases) if os.path.normcase(p) not in map(os.path.normcase, databases[:i])]
        choice = n1mm_logs.choose_log(databases, current[:2] if current else None)
        if choice is None:
            sys.exit("No log chosen.")
        path, nr, name = choice
        return path, nr, "log #{nr} {name}".format(nr=nr, name=name)

    source = 'from {cfg}'.format(cfg=os.path.basename(config_path))
    if not database:
        if not current:
            sys.exit("No database set in [n1mm] database, and N1MM's current database isn't in {ini}. "
                     "Set it, or run with --pick to choose.".format(ini=ini))
        database, source = current[0], "N1MM's current database"

    contest = config.get('n1mm', 'contest_nr').strip().lower()
    if contest in ('', 'all'):
        return database, None, "all logs ({source})".format(source=source)
    if contest == 'current':
        if not current or current[1] is None:
            sys.exit("contest_nr = current, but N1MM's current log isn't in {ini}.".format(ini=ini))
        return database, current[1], "log #{nr} {name} (N1MM's current log)".format(nr=current[1], name=current[2] or '')
    try:
        return database, int(contest), "log #{nr} ({source})".format(nr=int(contest), source=source)
    except ValueError:
        sys.exit("contest_nr must be a log number, 'current' or 'all', not {c!r}".format(c=contest))


def main():
    parser = argparse.ArgumentParser(description="Color callsigns in WSJT-X that are already in your N1MM Logger+ log.")
    parser.add_argument('-c', '--config', default=DEFAULT_CONFIG, help="config file (default: dupe_check.cfg beside this script)")
    parser.add_argument('--pick', action='store_true', help="choose the N1MM database and log from a list")
    parser.add_argument('--save-config', action='store_true', help="with --pick: save the choice in the config file")
    parser.add_argument('-v', '--verbose', action='store_true', help="print every WSJT-X message")
    parser.add_argument('-l', '--show-lookups', dest='show_lookups', action='store_true', default=None,
                        help="print every callsign as it's looked up (overrides show_lookups in the config file)")
    parser.add_argument('--no-show-lookups', dest='show_lookups', action='store_false',
                        help="print only callsigns already worked (overrides show_lookups in the config file)")
    args = parser.parse_args()
    if args.save_config and not args.pick:
        parser.error("--save-config goes with --pick")

    config = load_config(args.config)
    verbose = args.verbose or config.getboolean('dupe_check', 'verbose')
    show_lookups = args.show_lookups if args.show_lookups is not None else config.getboolean('dupe_check', 'show_lookups')
    match_my_call = config.getboolean('dupe_check', 'match_my_call')
    same_modes = ('FT8', 'FT4') if config.getboolean('dupe_check', 'include_ft4') else ('FT8',)

    database, contest_nr, which = choose_log(config, args.config, args.pick)
    if args.save_config:
        n1mm_logs.update_config_file(args.config, 'n1mm', {'database': database, 'contest_nr': contest_nr})
        print("Saved database = {db}, contest_nr = {nr} in {cfg}".format(db=database, nr=contest_nr, cfg=args.config))

    dupes = DupeDatabase(database, contest_nr)
    try:
        dupes.lookup('N9ADG')  # make sure the database can be read before listening to WSJT-X
    except (OSError, sqlite3.Error) as e:
        sys.exit("Can't read {db}: {e}".format(db=database, e=e))
    print("Checking callsigns against {db}, {which}".format(db=database, which=which))

    address, port = config.get('wsjtx', 'address'), config.getint('wsjtx', 'port')
    interface = config.get('wsjtx', 'interface').strip() or None
    # SimpleServer shares ordinary (non-multicast) ports, and on Windows a program on 127.0.0.1:2237 can take WSJT-X's
    # messages from one already on all addresses at 2237 - e.g. N1MM Logger+'s own WSJT-X support. So first make
    # sure nobody else has the port; multicast is fine to share, as every member gets its own copy.
    if not ipaddress.ip_address(address).is_multicast:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.bind(('', port))
        except OSError:
            dupes.close()
            sys.exit("Port {p} is in use by another program - often N1MM Logger+, for its own WSJT-X support. Listening"
                     " there too would take WSJT-X's messages away from it. See the [wsjtx] notes in"
                     " dupe_check.cfg.example about multicast.".format(p=port))
        finally:
            probe.close()
    try:
        s = pywsjtx.extra.simple_server.SimpleServer(address, port, timeout=2.0, interface=interface)
    except OSError as e:
        dupes.close()
        sys.exit("Can't listen on {a}:{p} ({e}). Another program - often N1MM Logger+ itself, for its own WSJT-X support -"
                 " probably has that port; see the [wsjtx] notes in dupe_check.cfg.example about multicast.".format(a=address, p=port, e=e))
    print("Listening for WSJT-X on {a}:{p}{i}; Ctrl-C to stop".format(a=address, p=port, i=" (interface {0})".format(interface) if interface else ''))

    my_call = None             # from WSJT-X's status messages
    cleared = set()            # (address, id) of each WSJT-X whose old scores we've cleared
    last_heard = time.time()   # when WSJT-X last sent anything (start counting from now)
    warned = False             # said "nothing from WSJT-X" for the current quiet spell
    dial_frequency = 14074000  # likewise
    try:
        while True:
            (pkt, addr_port) = s.rx_packet()
            if addr_port is None:
                if verbose:
                    print(".")
                if not warned and time.time() - last_heard >= SILENCE_WARNING:
                    warned = True
                    print("Nothing from WSJT-X for {n} seconds on {a}:{p}. Is WSJT-X running, and is its UDP Server"
                          " (Settings > Reporting) set to {a}, port {p}?".format(n=SILENCE_WARNING, a=address, p=port), flush=True)
                continue
            last_heard = time.time()
            if warned:
                warned = False
                print("Hearing WSJT-X now (from {a}:{p}).".format(a=addr_port[0], p=addr_port[1]), flush=True)
            if pkt is None:
                continue
            the_packet = pywsjtx.WSJTXPacketClassFactory.from_udp_packet(addr_port, pkt)
            if verbose:
                print(the_packet)

            # the first time we hear from a WSJT-X, clear any scores left over from an earlier run or another log
            wsjtx_id = getattr(the_packet, 'wsjtx_id', None)
            if wsjtx_id is not None and (addr_port, wsjtx_id) not in cleared:
                cleared.add((addr_port, wsjtx_id))
                s.send_packet(addr_port, pywsjtx.AnnotateCallsignPacket.Builder(
                    wsjtx_id, pywsjtx.AnnotateCallsignPacket.CLEAR_ALL, True, 0))
                if verbose:
                    print("Cleared WSJT-X {id}'s scores".format(id=wsjtx_id))

            if type(the_packet) == pywsjtx.StatusPacket:
                dial_frequency = the_packet.dial_frequency
                my_call = the_packet.de_call
                if my_call.find('/') >= 0:
                    my_call = '<' + my_call + '>'

            if type(the_packet) == pywsjtx.HeartBeatPacket:
                max_schema = max(the_packet.max_schema, MY_MAX_SCHEMA)
                reply_beat_packet = pywsjtx.HeartBeatPacket.Builder(the_packet.wsjtx_id, max_schema)
                s.send_packet(addr_port, reply_beat_packet)

            if type(the_packet) == pywsjtx.DecodePacket:
                if the_packet.message is None:
                    continue
                # get the callsign calling
                if match_my_call and not my_call:
                    continue  # no status message from WSJT-X yet, so we don't know who "me" is
                callsign = caller_in(the_packet.message, my_call if match_my_call else None)
                if callsign:
                    band = band_for(dial_frequency)
                    dupe_tuples = dupes.lookup(callsign)
                    dupe_score = calculate_dupe_score(band, dupe_tuples, same_modes)
                    # I just like saying "dupe tuple" in my head
                    if dupe_score > 0 or show_lookups or verbose:
                        print(lookup_line(callsign, band, dupe_score, dupe_tuples), flush=True)

                    if dupe_score >= 2000:
                        color_pkt = pywsjtx.HighlightCallsignPacket.Builder(the_packet.wsjtx_id, callsign,
                                                                            pywsjtx.QCOLOR.Red(),
                                                                            pywsjtx.QCOLOR.White(),  # RGBA(255, 50, 137, 48 ),
                                                                            False)
                        s.send_packet(addr_port, color_pkt)

                    if dupe_score > 0:
                        # WSJT-X caps scores at 50000; it shows them in Fox mode's Score column and sorts lowest first
                        score = min(dupe_score, pywsjtx.AnnotateCallsignPacket.MAX_SORT_ORDER)
                        annotate_pkt = pywsjtx.AnnotateCallsignPacket.Builder(the_packet.wsjtx_id, callsign, True, score)
                        s.send_packet(addr_port, annotate_pkt)
    except KeyboardInterrupt:
        print("Stopped.")
    finally:
        dupes.close()


if __name__ == "__main__":
    main()
