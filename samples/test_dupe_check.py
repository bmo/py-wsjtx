# Tests for dupe_check.py's message parsing and scoring:  python test_dupe_check.py   (from the samples folder)
import unittest

import dupe_check


class CallerIn(unittest.TestCase):
    def test_directed_message(self):
        self.assertEqual(dupe_check.caller_in('N9ADG K1ABC -12'), 'K1ABC')

    def test_cq_with_and_without_modifiers(self):
        for message in ('CQ K1ABC FN42', 'CQ DX K1ABC FN42', 'CQ POTA K1ABC', 'CQ 160 K1ABC FN42', 'QRZ K1ABC'):
            self.assertEqual(dupe_check.caller_in(message), 'K1ABC', message)

    def test_brackets_removed(self):
        self.assertEqual(dupe_check.caller_in('CQ NA <K1ABC/P> FN42'), 'K1ABC/P')

    def test_no_callsign(self):
        for message in ('CQ DX', 'CQ', 'TNX 73 GL'):
            self.assertIsNone(dupe_check.caller_in(message), message)

    def test_only_stations_calling_me(self):
        self.assertEqual(dupe_check.caller_in('N9ADG K1ABC -12', 'N9ADG'), 'K1ABC')
        self.assertEqual(dupe_check.caller_in('<N9ADG/MM> K1ABC R-05', '<N9ADG/MM>'), 'K1ABC')
        self.assertIsNone(dupe_check.caller_in('CQ DX K1ABC FN42', 'N9ADG'))
        self.assertIsNone(dupe_check.caller_in('W1AW K1ABC -12', 'N9ADG'))


class Scoring(unittest.TestCase):
    def test_ft4_optional(self):
        records = [('FT4', 14.0, 1)]
        self.assertEqual(dupe_check.calculate_dupe_score(14, records), 300)
        self.assertEqual(dupe_check.calculate_dupe_score(14, records, ('FT8', 'FT4')), 2000)

    def test_ft8_this_band_other_mode_other_band(self):
        records = [('FT8', 14.0, 1), ('CW', 14.0, 1), ('FT8', 7.0, 2)]
        self.assertEqual(dupe_check.calculate_dupe_score(14, records), 2000 + 300 + 2 * 20)

    def test_unknown_frequency_counts_as_20m(self):
        self.assertEqual(dupe_check.band_for(70200000), 14.0)
        self.assertEqual(dupe_check.band_for(7074000), 7)


class LookupLine(unittest.TestCase):
    def test_worked(self):
        line = dupe_check.lookup_line('YT0A', 14, 600, [('JTTY', 14.0, 2)])
        self.assertRegex(line, r'^\d\d:\d\d:\d\dZ  YT0A +14 MHz  score +600  JTTY 14 MHz x2$')

    def test_not_in_log(self):
        self.assertRegex(dupe_check.lookup_line('K1XYZ', 1.8, 0, []), r'Z  K1XYZ +1\.8 MHz  not in log$')


class AnnotateBuilder(unittest.TestCase):
    """ pywsjtx's AnnotateCallsignPacket.Builder must match WSJT-X's AnnotationInfo: id, callsign, bool, quint32. """

    def fields(self, packet):
        from pywsjtx.wsjtx_packets import PacketReader
        r = PacketReader(packet)
        return r.QInt32(), r.QString(), r.QString(), r.QInt8(), r.QUInt32()

    def test_remove_is_unsigned(self):
        packet = dupe_check.pywsjtx.AnnotateCallsignPacket.Builder('WSJT-X', 'K1ABC', True,
                                                                   dupe_check.pywsjtx.AnnotateCallsignPacket.REMOVE)
        self.assertEqual(self.fields(packet), (16, 'WSJT-X', 'K1ABC', 1, 0xFFFFFFFF))

    def test_sort_order_provided_is_sent(self):
        packet = dupe_check.pywsjtx.AnnotateCallsignPacket.Builder('WSJT-X', 'K1ABC', False, 0)
        self.assertEqual(self.fields(packet)[3], 0)


if __name__ == '__main__':
    unittest.main()
