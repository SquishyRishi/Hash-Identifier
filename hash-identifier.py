"""
Author: Rishi Sood
Project: Hash-Identifier
Description: A simple tool to identify the type of hash used in a given string.
"""

import sys
import argparse
from dataclasses import dataclass
from typing import Literal
from rich.console import Console
from rich.table import Table

Confidence = Literal["High", "Medium", "Low"]

@dataclass(frozen=True, slots=True)
class Candidates:
    algorithm:str
    confidence:Confidence
    
    # def __init__(self, algorithm:str, confidence:Confidence, explanation:str):
    #     self.algorithm = algorithm
    #     self.confidence = confidence
    #     self.explanation = explanation

    # def __repr__(self):
    #     return (
    #         f"Candidates(algorithm={self.algorithm!r}, "
    #         f"confidence={self.confidence!r}, "
    #         f"explanation={self.explanation!r})"
    #     )

    # def __eq__(self, other):
    #     if not isinstance(other, Candidates):
    #         return NotImplemented
    #     return (
    #         self.algorithm == other.algorithm
    #         and self.confidence == other.confidence
    #         and self.explanation == other.explanation
    #     )


PREFIX_RULES: list[tuple[str,str]] = [
    ("$argon2i$", "Argon2i"),
    ("$argon2d$", "Argon2d"),
    ("$argon2id$", "Argon2od"),
    
    ("$2a$", "bcrypt - 2a variant"),
    ("$2b$", "bcrypt - 2b variant"),
    ("$2x$", "bcrypt - 2x variant"),
    ("$2y$", "bcrypt - 2y variant"),
    
    ("$apr1$", "Apache MD5-crypt"),
    
    ("$1$", "MD5 crypt"),
    ("$2$", "bcrypt"),
    ("$5$", "SHA-256 crypt"),
    ("$6$", "SHA-512 crypt"),
    ("$sha1$", "SHA1-crypt"),
    
    ("$P$", "PHPass"),
    ("$H$", "PHPass"),
    ("$S$", "Drupal SHA-512"),
    
    ("pbkdf2_sha256$", "Django PBKDF2-SHA256"),
    ("pbkdf2_sha1$", "Django PBKDF2-SHA1"),
    ("bcrypt_sha256$", "Django bcrypt-SHA256"),
    ("argon2$", "Django Argon2 Wrapper"),
    
    ("{SHA}", "LDAP SHA"),
    ("{SSHA}", "LDAP SSHA"),
    ("{MD5}", "LDAP MD5"),
    ("{SMD5}", "LDAP SMD5"),
    ("{CRYPT}", "LDAP CRYPT"),
]

HEX_CHARSET: frozenset[str] = frozenset("0123456789abcdefABCDEF")
UPPER_CHARSET: frozenset[str] = frozenset("0123456789ABCDEF")

HEX_LENGTHS: dict[int, list[str]] = {
    16: ["MySQL323", "CRC-64"],
    32: ["MD5", "NTLM", "MD4", "RIPEMD-128"],
    40: ["SHA-1", "RIPEMD-160"],
    48: ["Tiger-192"],
    56: ["SHA-224", "SHA3-224"],
    64: ["SHA-256", "SHA3-256", "BLAKE2s-256", "RIPEMD-256"],
    80: ["RIPEMD-320"],
    96: ["SHA-384", "SHA3-384"],
    128: ["SHA-512", "SHA3-512", "BLAKE2b-512", "Whirpool"],
}

if __name__ == "__main__":
    sys.exit(main())