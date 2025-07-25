import os
import base64

from pycose.keys import RSAKey

PKEY = {
    'KTY': 'EC2',
    'CURVE': 'P_256',
    'ALG': 'ES256',
    'D': b"<\xe5\xbc;\x08\xadF\x1d\xc5\x0czR'T&\xbb\x91\xac\x84\xdc\x9ce\xbf\x0b,\x00\xcb\xdd\xbf\xec\xa2\xa5",
    'KID': b"demo-kid"
}

def base64_urldecode(v: str) -> bytes:
    """Urlsafe base64 decoding. This function will handle missing
    padding symbols.

    :returns: the decoded data in bytes, format, convert to str use method '.decode("utf-8")' on result
    :rtype: bytes
    """
    padded = f"{v}{'=' * divmod(len(v), 4)[1]}"
    return base64.urlsafe_b64decode(padded)

decoded_x = base64_urldecode("dGLQBwQIPWjc2aA6zRc06wlNVxiw72PMwJlEXHEvP-E")
decoded_d = base64_urldecode("NOHGihpyjNa_xBSd17Wr4ynkSM-afunMgpoPoFkelhI")

PKEY_ED25519 = {
    'KTY': 'OKP',
    'CURVE': 'Ed25519',
    'ALG': 'EdDSA',
    'D': decoded_d,
    'X': decoded_x,
    'KID': b"demo-kid-ed25519"
}

PKEY_RSA = {
    'KTY': 'RSA', 
    'E': b'\xd4\xf1\xf2o', 
    'N': b'[_\x81\\6y3\xbf\x01\xad\xba\xe26&\xcb\xa2g\xff\x97\xa1rv\xa7\x9a{\xfb\x01r^S\xfb\xefY\xb4\x14\xcesz\x99H\x02\xaf\xf5\xab\x18_\xac\xaaR\x13Q\xe6\xa0\x9a\x8c\x8a\x1f\x13\x0b9\xf3\xbb\xe1\x0b\xb9<\xe7\xc0\xffU\xa0\xcb\x1aw\xf2/\x11\x0e\xea^\x98:cp\x1f3\xc9\x81\x93e\x81\xb4\xb20s\xa6\xaaV\xf3\x03y\xb3\xd9\x93i\x14\xa7\xafi.\x08\xdey\x15s-V\x10\xf0\x0f+:E\x10\xec\xca\x93\x17\xecg\xaf!\x11\xe7\x91\xcdG7)\x83\xc3\xdd\xc2xp\xb2v_\xf2l\xc9\xc7\x15r\xf9\xa1U\xe9`\xde\xf1\xa9\xc2\xb6\xde\xebc|\xef\xb0s,\x10\xa1l\x81&\xcc\xb9\xfa\xb6\xffs\x1a9\x0c[7\xafJ\x1c\xd5\xb6\xc7?\x1c\x8fN\x1a\xde\x7f\xa4\x8f\xf6,\xed\x89b\x87\xcaXL\x8e}\xa5K\x0b\x9a\x8c\xb2\xd2\x91\x0f\xedI\x8e\x8fYq#\x8c\xd1\x02\xe2B\xff\xf1\x1dT\x15\xb1I\xe8\xd8\xfc[\xd5Y\x9ab\xcc\xe3\xff\xac\xfa\x85', 
    'KEY_OPS': ['SIGN']
}