#
# Utility class to help out with Qt Color Values.
#
class QCOLOR:
    SPEC_RGB = 1
    SPEC_INVALID = 0

    def __init__(self, spec, alpha, red, green, blue):
        self.spec = spec
        self.red = alpha
        self.green = red
        self.blue = green
        self.alpha = blue

    @classmethod
    def Black(cls):
        return QCOLOR(QCOLOR.SPEC_RGB, 255, 0, 0,0)

    @classmethod
    def Red(cls):
        return QCOLOR(QCOLOR.SPEC_RGB, 255, 255, 0, 0)
    @classmethod
    def RGBA(cls, alpha, red, green, blue):
        return QCOLOR(QCOLOR.SPEC_RGB, alpha, red, green, blue)

    @classmethod
    def White(cls):
        return QCOLOR(QCOLOR.SPEC_RGB, 255,255,255,255)


