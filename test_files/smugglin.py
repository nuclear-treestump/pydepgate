"""cHJpbnQoIltkZW1vXSBkb2NzdHJpbmctc211Z2dsZWQgaW5lcnQgcGF5bG9hZC4gV291bGQgaGF2ZSBydW4gb24gaW1wb3J0LiIp"""

# DEMO FIXTURE: Docstring smuggling
# Demonstrates: DENS050 (high-entropy docstring), DENS051 (dynamic
# __doc__ piped to a callable), DENS010 (high-entropy string),
# DENS011 (base64 alphabet), ENC001 (encoded payload + exec).
# Inert: __doc__ decodes to a print statement.

import base64

# The shape of this attack: the module's docstring IS the payload.
# Static analysis that reads source comments and docstrings sees
# nothing executable; the payload only materializes when __doc__
# is read at runtime and piped through a decoder into exec.
exec(base64.b64decode(__doc__))

# In a real attack, the module would continue to do its
# advertised job here so that nothing seems amiss.
def public_api():
    """The function this module pretends to be about."""
    print("[demo] public_api called")


if __name__ == "__main__":
    public_api()