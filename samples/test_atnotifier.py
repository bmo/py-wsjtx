# Tests for atnotifier.py's message parsing and scoring:  python test_atnotifier.py   (from the samples folder)
import unittest

import atnotifier


class CallerIn(unittest.TestCase):
    def test_directed_message(self):
        self.assertEqual(atnotifier.caller_in('N9ADG K1ABC -12'), 'K1ABC')

    def test_cq_with_and_without_modifiers(self):
        for message in ('CQ K1ABC FN42', 'CQ DX K1ABC FN42', 'CQ POTA K1ABC', 'CQ 160 K1ABC FN42', 'QRZ K1ABC'):
            self.assertEqual(atnotifier.caller_in(message), 'K1ABC', message)

    def test_brackets_removed(self):
        self.assertEqual(atnotifier.caller_in('CQ NA <K1ABC/P> FN42'), 'K1ABC/P')

    def test_no_callsign(self):
        for message in ('CQ DX', 'CQ', 'TNX 73 GL'):
            self.assertIsNone(atnotifier.caller_in(message), message)

    def test_only_stations_calling_me(self):
        self.assertEqual(atnotifier.caller_in('N9ADG K1ABC -12', 'N9ADG'), 'K1ABC')
        self.assertEqual(atnotifier.caller_in('<N9ADG/MM> K1ABC R-05', '<N9ADG/MM>'), 'K1ABC')
        self.assertIsNone(atnotifier.caller_in('CQ DX K1ABC FN42', 'N9ADG'))
        self.assertIsNone(atnotifier.caller_in('W1AW K1ABC -12', 'N9ADG'))


class Scoring(unittest.TestCase):
    def test_ft4_optional(self):
        records = [('FT4', 14.0, 1)]
        self.assertEqual(atnotifier.calculate_dupe_score(14, records), 300)
        self.assertEqual(atnotifier.calculate_dupe_score(14, records, ('FT8', 'FT4')), 2000)

    def test_ft8_this_band_other_mode_other_band(self):
        records = [('FT8', 14.0, 1), ('CW', 14.0, 1), ('FT8', 7.0, 2)]
        self.assertEqual(atnotifier.calculate_dupe_score(14, records), 2000 + 300 + 2 * 20)

    def test_unknown_frequency_counts_as_20m(self):
        self.assertEqual(atnotifier.band_for(70200000), 14.0)
        self.assertEqual(atnotifier.band_for(7074000), 7)


class LookupLine(unittest.TestCase):
    def test_worked(self):
        line = atnotifier.lookup_line('YT0A', 14, 600, [('JTTY', 14.0, 2)])
        self.assertRegex(line, r'^\d\d:\d\d:\d\dZ  YT0A +14 MHz  score +600  JTTY 14 MHz x2$')

    def test_not_in_log(self):
        self.assertRegex(atnotifier.lookup_line('K1XYZ', 1.8, 0, []), r'Z  K1XYZ +1\.8 MHz  not in log$')


class AnnotateBuilder(unittest.TestCase):
    """ pywsjtx's AnnotateCallsignPacket.Builder must match WSJT-X's AnnotationInfo: id, callsign, bool, quint32. """

    def fields(self, packet):
        from pywsjtx.wsjtx_packets import PacketReader
        r = PacketReader(packet)
        return r.QInt32(), r.QString(), r.QString(), r.QInt8(), r.QUInt32()

    def test_remove_is_unsigned(self):
        packet = atnotifier.pywsjtx.AnnotateCallsignPacket.Builder('WSJT-X', 'K1ABC', True,
                                                                   atnotifier.pywsjtx.AnnotateCallsignPacket.REMOVE)
        self.assertEqual(self.fields(packet), (16, 'WSJT-X', 'K1ABC', 1, 0xFFFFFFFF))

    def test_sort_order_provided_is_sent(self):
        packet = atnotifier.pywsjtx.AnnotateCallsignPacket.Builder('WSJT-X', 'K1ABC', False, 0)
        self.assertEqual(self.fields(packet)[3], 0)


class QColorRoundTrip(unittest.TestCase):
    """ PacketReader.QColor() reads back what HighlightCallsignPacket.Builder writes. """

    def read_colors(self, background, foreground):
        from pywsjtx.wsjtx_packets import PacketReader
        packet = atnotifier.pywsjtx.HighlightCallsignPacket.Builder('WSJT-X', 'K1ABC', background, foreground, False)
        r = PacketReader(packet)
        r.QInt32(), r.QString()
        self.assertEqual(r.QString(), 'K1ABC')
        return r.QColor(), r.QColor()

    def rgba(self, color):
        return (color.spec, color.alpha, color.red, color.green, color.blue)

    def test_named_colors(self):
        QCOLOR = atnotifier.pywsjtx.QCOLOR
        background, foreground = self.read_colors(QCOLOR.Red(), QCOLOR.White())
        self.assertEqual(self.rgba(background), (QCOLOR.SPEC_RGB, 255, 255, 0, 0))
        self.assertEqual(self.rgba(foreground), (QCOLOR.SPEC_RGB, 255, 255, 255, 255))

    def test_rgba_keeps_green_and_blue_apart(self):
        QCOLOR = atnotifier.pywsjtx.QCOLOR
        background, _ = self.read_colors(QCOLOR.RGBA(200, 10, 20, 30), QCOLOR.Black())
        self.assertEqual(self.rgba(background), (QCOLOR.SPEC_RGB, 200, 10, 20, 30))

    def test_no_color(self):
        QCOLOR = atnotifier.pywsjtx.QCOLOR
        background, _ = self.read_colors(QCOLOR.Uncolor(), QCOLOR.Uncolor())
        self.assertEqual(background.spec, QCOLOR.SPEC_INVALID)


class CallsignColors(unittest.TestCase):
    def rgb(self, color):
        return (color.red, color.green, color.blue)

    def test_names_and_codes(self):
        self.assertEqual(self.rgb(atnotifier.parse_color('orange')), (255, 165, 0))
        self.assertEqual(self.rgb(atnotifier.parse_color('LightBlue')), (0xad, 0xd8, 0xe6))
        self.assertEqual(self.rgb(atnotifier.parse_color('#12AbEf')), (0x12, 0xab, 0xef))
        self.assertEqual(self.rgb(atnotifier.parse_color('#f80')), (0xff, 0x88, 0x00))
        for bad in ('#12345', 'notacolor', '#ggg'):
            with self.assertRaises(ValueError):
                atnotifier.parse_color(bad)

    def test_text_color_contrasts(self):
        self.assertEqual(self.rgb(atnotifier.text_color_for(atnotifier.parse_color('yellow'))), (0, 0, 0))
        self.assertEqual(self.rgb(atnotifier.text_color_for(atnotifier.parse_color('navy'))), (255, 255, 255))

    def test_file(self):
        import os, tempfile
        path = os.path.join(tempfile.mkdtemp(), 'colors.txt')
        with open(path, 'w') as f:
            f.write("# needed by the DXpedition team\n"
                    "; another comment\n"
                    "\n"
                    "vk0ek   orange\n"
                    "3Y0J    #ff00ff  white   ; Bouvet\n"
                    "<K1ABC/P>, gold\n"
                    "W1AW\n"
                    "K2XX    notacolor\n")
        colors, problems = atnotifier.read_callsign_colors(path)
        self.assertEqual(sorted(colors), ['3Y0J', 'K1ABC/P', 'VK0EK'])
        self.assertEqual(self.rgb(colors['VK0EK'][0]), (255, 165, 0))
        self.assertEqual(self.rgb(colors['VK0EK'][1]), (0, 0, 0), "black text on orange")
        self.assertEqual(self.rgb(colors['3Y0J'][1]), (255, 255, 255), "text color as given")
        self.assertEqual([p.split(':')[0] for p in problems], ['line 7', 'line 8'])

    def test_old_config_section_still_read(self):
        import os, tempfile
        path = os.path.join(tempfile.mkdtemp(), 'dupe_check.cfg')
        with open(path, 'w') as f:
            f.write("[dupe_check]\nmatch_my_call = false\nshow_lookups = false\n")
        config = atnotifier.load_config(path)
        self.assertFalse(config.getboolean('atnotifier', 'match_my_call'))
        self.assertFalse(config.getboolean('atnotifier', 'show_lookups'))
        self.assertEqual(config.get('atnotifier', 'callsign_colors'), 'atnotifier_colors.txt')


if __name__ == '__main__':
    unittest.main()
