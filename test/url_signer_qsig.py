#!/bin/python

import os
import optparse
import sys

sys.path.append("../qwilt/qsig")
from qsig import Qsig, QsigError

# ======================================================================================================================
if __name__ == "__main__":

    p = optparse.OptionParser()
    p.add_option("-p", "--path", type="string", default="/demo/path/for/signing?with=args",
                        help="Path to sign [default: '%default']")
    p.add_option("--kid", type="int", default=0,
                        help="'kid' to set in token [default: '%default']")
    p.add_option("--key", type="string", default="secret0",
                        help="secret key to sign with [default: '%default']")
    p.add_option("-t", "--typ", type="choice", choices=Qsig.kTypes, default=Qsig.kTypSgn,
                        help="'typ' to use for signing. Must be one of: %s [default: '%%default']"%(Qsig.kTypes))
    p.add_option("--cnt", type="int", default=-1,
                        help="Value for 'cnt', when 'typ' is 'sgn' [default: '%default']")
    p.add_option("--off", type="int", default=0,
                        help="Value for 'off', when 'typ' is 'sgn' [default: '%default']")
    p.add_option("--rgx", type="string", default="(.*)",
                        help="Value for regex match rule, when 'typ' is one of the regex types [default: '%default']")
    p.add_option("--rgb", type="string", default="$1",
                        help="Value for regex build rule, when 'typ' is one of the regex match & hash types [default: '%default']")
    p.add_option("--cip", type="string", default=None,
                        help="Value for client IP [default: None")
    p.add_option("--exp", type="int", default=120,
                        help="Seconds Expiration from Current Time [default: 120")
    p.add_option("--host", type="string", default="",
                            help="Hostname to add to request")


    (options, args) = p.parse_args()

    try:
        
        s = Qsig(kid=options.kid, key=options.key, ip=options.cip, window_seconds=options.exp)

        if options.typ == Qsig.kTypSgn:
            if options.cnt > 0:
                sig = s.generate_sgn_token(options.path, options.cnt, options.off)
            else:
                sig = s.generate_last_segment_sgn_token(options.path)
        elif options.typ == Qsig.kTypRgm:
            sig = s.generate_rgm_token(options.path, options.rgx)
        elif options.typ == Qsig.kTypRgh:
            sig = s.generate_rgh_token(options.path, options.rgx, options.rgb)
        elif options.typ == Qsig.kTypCfgRgh:
            sig = s.generate_cfg_rgh_token(options.path, options.rgx, options.rgb)
        elif options.typ == Qsig.kTypAll:
            sig = s.generate_all_token(options.path)
        else:
            raise Exception("Unsupported type: %s", options.typ)

        final_url = s.build_url(options.path, sig)
        if options.host:
            print "https://" + options.host + final_url
        else:
            print final_url

    except Exception as ex:
        print "Error: %s" % (ex)


