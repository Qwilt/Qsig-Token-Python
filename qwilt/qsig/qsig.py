# -*- coding: utf-8 -*-

import binascii
import hashlib
import hmac
import os
import re
import sys
import time
import json
import base64

if sys.version_info[0] >= 3:
    from urllib.parse import quote_plus

    def encode(s):
        return s.encode('utf-8')
    
    def castToBytes(strOrBytes):
        # encoding a zero-length str returns a str, not bytes :-(
        if len(strOrBytes)==0:
            return b''
        if strOrBytes and isinstance(strOrBytes, str):
            # iso-8859-1 is a simple 1:1 mapping, no need to check length and such
            strOrBytes = strOrBytes.encode('iso-8859-1')
        return strOrBytes
    
    def decode(s):
        return s.decode('utf-8')
else:
    from urllib import quote_plus

    def encode(s):
        return s
    
    def decode(s):
        return s
    
    def castToBytes(strOrBytes):
        return strOrBytes

# Force the local timezone to be GMT.
os.environ['TZ'] = 'GMT'

class QsigError(Exception):
    def __init__(self, text):
        self._text = text

    def __str__(self):
        return 'QsigError:{0}'.format(self._text)

    def _getText(self):
        return str(self)
    text = property(_getText, None, None,
        'Formatted error text.')


class Qsig:

    kTokenName = "qsig"

    # Values for Token insertion location
    kTokenLocationFirstInPath = 0
    kTokenLocationUriParam = 1
    kTokenLocationCookie = 2

    # Values for "typ"
    kTypAll     = "all"
    kTypSgn     = "sgn"
    kTypRgm     = "rgm"
    kTypRgh     = "rgh"
    kTypCfgRgh  = "cfg-rgh"

    kTypes = [kTypAll, kTypSgn, kTypRgm, kTypRgh, kTypCfgRgh]

    @staticmethod
    def md5(msg):
        hsh = hashlib.md5()
        hsh.update(encode(msg))
        return hsh.hexdigest()

    def __init__(self, token_type=None, token_name='__token__',
                 key=None, ip=None,
                 start_time=None, end_time=None, window_seconds=None,
                 escape_early=False, verbose=False,
                 token_location=None, is_trim_jwt_header=True, kid=0, base_header_dict=None, base_paylod_dict=None):
        
        if key is None or len(key) <= 0:
            raise QsigError('You must provide a secret in order to '
                'generate a new token.')

        self.token_type = token_type
        self.token_name = token_name
        self.key = key
        self.ip = ip
        self.start_time = start_time
        self.end_time = end_time
        self.window_seconds = window_seconds
        self.escape_early = escape_early
        self.verbose = verbose

        if token_location is None:
            self.token_location = self.kTokenLocationFirstInPath
        else:
            self.token_location = token_location

        self.is_trim_jwt_header = is_trim_jwt_header

        self.header_dict = {}
        if base_header_dict:
            self.header_dict.update(base_header_dict)
        self.header_dict["alg"] = "HS256"

        self.paylod_dict = {}
        if base_paylod_dict:
            self.paylod_dict.update(base_paylod_dict)
        self.paylod_dict["kid"] = kid


    def _escape_early(self, text):
        if self.escape_early:
            def toLower(match):
                return match.group(1).lower()
            return re.sub(r'(%..)', toLower, quote_plus(text))
        else:
            return text

    def _generate_token(self, path, payload_dict):
        start_time = self.start_time
        end_time = self.end_time

        if str(start_time).lower() == 'now':
            start_time = int(time.mktime(time.gmtime()))
        elif start_time:
            try:
                if int(start_time) <= 0:
                    raise QsigError('start_time must be ( > 0 )')    
            except:
                raise QsigError('start_time must be numeric or now')

        if end_time:
            try:
                if int(end_time) <= 0:
                    raise QsigError('end_time must be ( > 0 )')
            except:
                raise QsigError('end_time must be numeric')

        if self.window_seconds:
            try:
                if int(self.window_seconds) <= 0:
                    raise QsigError('window_seconds must be ( > 0 )')
            except:
                raise QsigError('window_seconds must be numeric')
                
        if end_time is None:
            if self.window_seconds:
                if start_time is None:
                    # If we have a window_seconds without a start time,
                    # calculate the end time starting from the current time.
                    end_time = int(time.mktime(time.gmtime())) + \
                        self.window_seconds
                else:
                    end_time = start_time + self.window_seconds
            else:
                raise QsigError('You must provide an expiration time or '
                    'a duration window ( > 0 )')
        
        if start_time and (end_time <= start_time):
            raise QsigError('Token will have already expired.')

        if self.verbose:
            print('''
Qwilt Token Generation Parameters
Token Type      : {0}
Token Name      : {1}
Key/Secret      : {2}
IP              : {3}
Start Time      : {4}
End Time        : {5}
Window(seconds) : {6}
Escape Early    : {7}
PATH            : {8}
Generating token...'''.format(self.token_type if self.token_type else '',
                            self.token_name if self.token_name else '',
                            self.key if self.key else '',
                            self.ip if self.ip else '',
                            start_time if start_time else '',
                            end_time if end_time else '',
                            self.window_seconds if self.window_seconds else '',
                            self.escape_early if self.escape_early else '',
                            'url: ' + path))

        hash_source = []
        new_token = []

        if self.ip:
            payload_dict["cip"] = self._escape_early(self.ip)

        payload_dict["exp"] = end_time

        header_json  = json.dumps(self.header_dict, separators=(',', ':'), sort_keys=True)
        payload_json = json.dumps(payload_dict, separators=(',', ':'), sort_keys=True)
               
        header64  = base64.urlsafe_b64encode(encode(header_json.replace("=", "")))
        payload64 = base64.urlsafe_b64encode(encode(payload_json.replace("=", "")))

        if self.verbose:
            print('''
Qwilt JWT
Header Json      : {0}
Payload Json     : {1}
Generating token...'''.format(header_json,
                            payload_json))

        base = "%s.%s" % (decode(header64), decode(payload64))
        _hmac = hmac.new(castToBytes(self.key), msg=castToBytes(base), digestmod=getattr(hashlib, 'sha256'))        
        _sig  = base64.urlsafe_b64encode(_hmac.digest())
        sigNe = decode(_sig).replace("=", "")
        sig = "%s.%s" % (base, sigNe)


        if self.is_trim_jwt_header:
            sig = re.sub("^[^\.]+\.", "", sig)

        return sig

    # Sign JWT by regex typs
    def sign_path_by_regex(self, url, payload, rgx, rgb=None):

        m = re.search(rgx, url)
        if not m:
            raise QsigError("Can't extract path, no match on regex: regex='%s', path='%s'", rgx, url)

        if rgb:
            path_to_hash = rgb
            for i, value in enumerate(m.groups()):
                path_to_hash = re.sub("\$%d"%(i+1), value, path_to_hash)

            payload["hsh"] = self.md5(path_to_hash)

        return self._generate_token(url, payload)

    # Sign JWT by typ 'all'
    def generate_all_token(self, url):

        payload = self.paylod_dict.copy()
        payload["typ"] = self.kTypAll
        payload["hsh"] = self.md5(url)

        return self._generate_token(url, payload)

    # Sign JWT by typ 'sgn'
    def generate_sgn_token(self, url, count, offset=0):

        payload = self.paylod_dict.copy()

        try:
            if int(count)<=0:
                raise QsigError("Count must be greater then 0 and it is %s" % (count))
        except Exception:
            raise QsigError("Count must be a numeric vaklue and it is %s" % (count))

        try:
            if int(offset)<0:
                raise QsigError("Offset cannot be negative and it is %s" % (count))
        except Exception:
            raise QsigError("Offset must be a numeric vaklue and it is %s" % (count))

        payload["typ"] = self.kTypSgn
        payload["cnt"] = count

        if offset:
            payload["off"] = offset

        m = re.match("((/[^/?]+){%s})((/[^/?]+){%s})"%(offset, count), url)
        if not m:
            raise QsigError("Can't extract path, not enough segments: off=%s, cnt=%s, path='%s'" % (offset, count, url))
        url_to_hash = m.group(3)
        payload["hsh"] = self.md5(url_to_hash)

        return self._generate_token(url, payload)

    # Sign JWT by typ 'sgn' based on last segment
    def generate_last_segment_sgn_token(self, url, offset=0):
        count = os.path.dirname(url).count("/") - offset
        return self.generate_sgn_token(url, count, offset)

    # Sign JWT by typ 'cfg-rgh'
    def generate_cfg_rgh_token(self, url, rgx, rgb):

        payload = self.paylod_dict.copy()
        payload["typ"] = self.kTypCfgRgh
        return self.sign_path_by_regex(url, payload, rgx, rgb)

    # Sign JWT by typ 'rgh'
    def generate_rgh_token(self, url, rgx, rgb):

        payload = self.paylod_dict.copy()
        payload["typ"] = self.kTypRgh
        payload["rgx"] = rgx
        payload["rgb"] = rgb
        return self.sign_path_by_regex(url, payload, rgx, rgb)

    # Sign JWT by typ 'rgm'
    def generate_rgm_token(self, url, rgx):

        payload = self.paylod_dict.copy()
        payload["typ"] = self.kTypRgm
        payload["rgx"] = rgx
        return self.sign_path_by_regex(url, payload, rgx, None)

    def build_url(self, url, sig):

        # Return token to use
        if self.token_location == self.kTokenLocationFirstInPath:
            return "/%s=%s%s" % (self.kTokenName, sig, url)

        elif self.token_location == self.kTokenLocationUriParam:
            if "?" in url:
                return "%s&%s=%s" % (url, self.kTokenName, sig)
            else:
                return "%s?%s=%s" % (url, self.kTokenName, sig)

        else:
            # Caller should add as "Cookie" header
            return "%s=%s" % (self.kTokenName, sig)

