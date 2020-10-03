class DmarcRecord:
    def __init__(self, v='DMARC1', p='', sp='', adkim='', aspf='', pct='', ri='', fo='', rf='', rua='', ruf=''):
        self.v = v
        self.p = p
        self.sp = sp
        self.adkim = adkim
        self.aspf = aspf
        self.pct = pct
        self.ri = ri
        self.fo = fo
        self.rf = rf
        self.rua = rua
        self.ruf = ruf
