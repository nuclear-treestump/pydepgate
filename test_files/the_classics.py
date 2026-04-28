# DEMO FIXTURE: Byte-array payload assembly
# Demonstrates: DENS042 (large byte-range integer array),
# DENS041 (deeply nested lambdas/comprehensions), DENS040
# (disproportionate AST depth from functional-style obfuscation).
# Inert: array decodes to a print message, no shellcode involved.

"""Embedded resource loader (totally legitimate, do not look here)."""


# 122 integers in the 0-255 range. In a real attack this
# would be x86 shellcode, a URL, or a stage-two payload to be passed
# to ctypes or written to disk and executed.
_DATA = [
    91, 100, 101, 109, 111, 93, 32, 105, 110, 101, 114, 116,
    32, 112, 97, 121, 108, 111, 97, 100, 32, 114, 101, 97,
    115, 115, 101, 109, 98, 108, 101, 100, 32, 102, 114, 111,
    109, 32, 105, 110, 116, 101, 103, 101, 114, 32, 97, 114,
    114, 97, 121, 46, 32, 73, 110, 32, 97, 32, 114, 101,
    97, 108, 32, 97, 116, 116, 97, 99, 107, 32, 116, 104,
    105, 115, 32, 119, 111, 117, 108, 100, 32, 104, 97, 118,
    101, 32, 98, 101, 101, 110, 32, 120, 56, 54, 32, 115,
    104, 101, 108, 108, 99, 111, 100, 101, 32, 111, 114, 32,
    97, 32, 100, 101, 99, 111, 100, 101, 100, 32, 85, 82,
    76, 46
]


# Functional-style decode chain. Real attacks use this to make the
# call graph hard to follow with grep and to resist naive AST
# pattern matching.
_assemble = (
    lambda data: (
        lambda chars: (
            lambda joiner: (
                lambda f: f(joiner, chars)
            )(lambda j, c: j.join(c))
        )("")
    )([chr(b) for b in data])
)


# At runtime this prints the demo message. In a real attack the
# assembled string would be fed to exec(), ctypes.CDLL(), or
# subprocess.Popen().
_payload = _assemble(_DATA)
print(_payload)