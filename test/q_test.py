import os
import sys
import binascii
import traceback


dir_path = os.path.dirname(os.path.realpath(__file__))
parent = os.path.dirname(dir_path)
sys.path.append("%s/qwilt/qsig" % parent)
from qsig import Qsig, QsigError

if sys.version_info[0] >= 3:
    def encode(s):
        return s.encode('utf-8')
else:
    def encode(s):
        return s

    

url = "/sign/base/dir/of/path/because/cnt/is/set/to/minus1"
rgx = """/sign/base/dir/of/path/because/cnt/is/set/to/minus(\d+)"""
rgb = "$1"
type = "sgn"
cnt = -1
key = "abdabcabcd"



signer = Qsig(key=key, window_seconds=120, start_time=100000, verbose=True)
print ("I am going to sign url \"%s\" with key \"%s\"" % (url, key))

# all
print (" ")
print ("all signature")
try:
    sig = signer.generate_all_token(url)    
except Exception as ex:    
    print ("Signing failed with error: %s" % (ex))
    sys.exit(1)
print ("Signing succeed. Signature is %s" % (sig))
final_url = signer.build_url(url, sig)
print ("URL is: %s" % (final_url))

# sgn last
print (" ")
print ("sgn signature - last in segment")
try:
    sig = signer.generate_last_segment_sgn_token(url)
except Exception as ex:    
    print ("Signing failed with error: %s" % (ex))
    sys.exit(1)
print ("Signing succeed. Signature is %s" % (sig))
final_url = signer.build_url(url, sig)
print ("URL is: %s" % (final_url))

# sgn
print (" ")
print ("sgn signature")
try:
    sig = signer.generate_sgn_token(url, count=5)
except Exception as ex:
    print ("Signing failed with error: %s" % (ex))
    sys.exit(1)
print ("Signing succeed. Signature is %s" % (sig))
final_url = signer.build_url(url, sig)
print ("URL is: %s" % (final_url))

# cfg-rgh
print (" ")
print ("cfg-rgh signature")
try:
    sig = signer.generate_cfg_rgh_token(url, rgx, rgb)
except Exception as ex:
    print ("Signing failed with error: %s" % (ex))
    sys.exit(1)
print ("Signing succeed. Signature is %s" % (sig))
final_url = signer.build_url(url, sig)
print ("URL is: %s" % (final_url))

# rgh
print (" ")
print ("rgh signature")
try:
    sig = signer.generate_rgh_token(url, rgx, rgb)
except Exception as ex:
    print ("Signing failed with error: %s" % (ex))
    sys.exit(1)
print ("Signing succeed. Signature is %s" % (sig))
final_url = signer.build_url(url, sig)
print ("URL is: %s" % (final_url))

# rgm
print (" ")
print ("rgm signature")
try:
    sig = signer.generate_rgm_token(url, rgx)
except Exception as ex:
    print ("Signing failed with error: %s" % (ex))
    sys.exit(1)
print ("Signing succeed. Signature is %s" % (sig))
final_url = signer.build_url(url, sig)
print ("URL is: %s" % (final_url))


sys.exit(0)




