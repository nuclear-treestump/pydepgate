# DEMO FIXTURE: Unicode trickery
# Demonstrates: DENS021 (confusable l/O/I single-char identifiers),
# DENS030 (invisible Unicode characters: RTL override, zero-width space),
# DENS031 (Cyrillic homoglyphs in identifiers).
# Inert: only contains print statements.

"""Module that totally definitely does what you think it does."""


# This identifier looks like "log" but the second character is
# Cyrillic U+043E, not ASCII U+006F. A grep for "log" misses it.
def lоg(message):
    """A log helper. Or is it?"""
    print(f"[demo log] {message}")


# Here's another one: "data" but with Cyrillic 'a' (U+0430).
def get_dаta():
    """Fetch data from the safe place."""
    print("[demo] returning safe data")
    return {"safe": True}


# Trojan-Source-style invisible character on the next line. The
# RTL override (U+202E) reorders the rendered text without changing
# what Python parses. There is also a zero-width space (U+200B)
# embedded inside the string literal below.
RECEIPT = "user_id​=admin"  # zero-width space hides in plain sight
WARNING = "‮safe content only"  # RTL override invisible to readers

# Confusable single-character identifiers (PEP 8 forbids these
# precisely because they look like 1, 0, 1).
l = "lowercase L can read as one"
O = 0
I = 1

# Use the homoglyph functions so they don't get optimized out
# by static-analysis tools that prune unused names.
lоg("hello")
get_dаta()

print(f"[demo] {RECEIPT!r} {WARNING!r} l={l} O={O} I={I}")