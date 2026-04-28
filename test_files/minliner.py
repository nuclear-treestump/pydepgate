# DEMO FIXTURE: Heavy one-line minification
# Demonstrates: DENS001 (token density), DENS002 (semicolon chaining),
# DENS010 (high-entropy strings), DENS011 (base64 alphabet),
# DENS040 (AST depth disproportionate to line count),
# DENS041 (lambda nesting), ENC001 (encoded payload + exec).
# Inert: the encoded blob decodes to a print statement.

"""Auto-generated bundle. Do not edit."""

import base64,zlib,sys,os;_=lambda x:x;_a=lambda f:lambda *a,**k:f(*a,**k);_b=lambda d:base64.b64decode(d);_c=lambda d:zlib.decompress(d);_d=(lambda p:lambda:exec(_b(p)))("cHJpbnQoIltkZW1vXSBtaW5pZmllZCBvbmUtbGluZXIuIEFsbCByZWFsIHdvcmsgd2FzIGhpZGRlbiBpbiB0aGUgZGVuc2UgbGluZSBhYm92ZS4iKQ==");_e="QWxsX3RoZV93b3JsZF9pc19hX3N0YWdlX2J1dF9ub3RfcmVhbGx5X2RlbW9fb25seQ==";_f=lambda *a:[*a];_g={i:chr(i)for i in range(32,127)};_h=(lambda x,y,z:(lambda w:w(x,y,z))(lambda a,b,c:[a,b,c]))(1,2,3)


class _Cfg:_v=1;_n="bundle";_x=staticmethod(lambda *a:None);_y=lambda s,*a:s


_d()