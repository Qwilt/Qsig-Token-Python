Qsig-Token-Python: Qwilt Edge Authorization Token for Python
=================================================================

Qsig-Token-Python is Qwilt Edge Authorization Token in the First path segment, Query String, and Cookie for a client.


Example
-------

.. code-block:: python

    from qwilt.qsig import Qsig, QsigError
    import requests # just for this example

    URL = "/path/to/content"
    HOSTNAME = "www.qwilt.com"
    WINDOW_SEC = 120
    KEY = "abdabcabcd"

* KEY should be a string of hexadecimal digits with even-length.

.. code-block:: python

    signer = Qsig(key=KEY, window_seconds=WINDOWS_SEC, token_location = Qsig.kTokenLocationFirstInPath)
    sig = signer.generate_last_segment_sgn_token(URL)
    signed_url = signer.build_url(URL, sig)
    request_url = "http://{0}{1}".format(HOSTNAME, signed_url)
    response = requests.get(request_url)
    print(response)
  
Usage
-----
**Qsig Class**

.. code-block:: python

    class Qsig(self, token_type=None, token_name='__token__',
                 key=None, ip=None,
                 start_time=None, end_time=None, window_seconds=None,
                 escape_early=False, verbose=False,
                 token_location=None, is_trim_jwt_header=True, kid=0, base_header_dict=None, base_paylod_dict=None):

====================  ===================================================================================================
 Parameter             Description
====================  ===================================================================================================
 token_type            Select a preset. (Not Used) 
 token_name            Parameter name for the new token. [Default: '__token__']
 key                   Secret required to generate the token. It must be hexadecimal digit string with even-length.
 ip                    IP Address to restrict this token to. (Troublesome in many cases (roaming, NAT, etc) so not often used)
 start_time            What is the start time? (Use string 'now' for the current time)
 end_time              When does this token expire? end_time overrides window_seconds
 window_seconds        How long is this token valid for?
 escape_early          Causes strings to be 'url' encoded before being used.
 verbose               Print all parameters.
 token_location        The token location - see "Token Locations" below [Default: first is path]
 is_trim_jwt_header    Weather to trim the first segment part of the token [Default: true]
 kid                   Key ID to use - when the content provider is configuring multiple keys [Detault: 0]
 base_header_dict      Allows adding more headers to the JWT header (for debugging)
 base_payload_dict     Allows adding more fields to the JWT payload (for debugging)
====================  ===================================================================================================

**Qsig's Methods**

================================  ===================================================================================================
 Method                                             Description
================================  ===================================================================================================
 generate_all_token                                 Generate a signature based on the entire URL
 generate_sgn_token                                 Generate a signature based on segment count
 generate_last_segment_sgn_token                    Generate a signature based on all URL but the last segment
 generate_cfg_rgh_token                             Generate a signature based on predefined regular expression and build rule
 generate_rgh_token                                 Generate a signature based on in-token regular expression and build rule
 generate_rgm_token                                 Generate a signature based on in-token regular expression without build rule
 build_url                                          Signs the URL - place the token in the chosen location
================================  ===================================================================================================

**Token Locations**

================================  ===================================================================================================
 Value                                              Description
================================  ===================================================================================================
 kTokenLocationFirstInPath                          Locate token as first path item
 kTokenLocationUriParam                             Locate token as a URI parameter
 kTokenLocationCookie                               Locate token as a Cookie header
================================  ===================================================================================================

Test
----
"/test" directory includes code examples for internal usage.