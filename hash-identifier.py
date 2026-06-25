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

#----------------------------------------------------------------------------------

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

#----------------------------------------------------------------------------------

PREFIX_RULES: list[tuple[str,str]] = [
    ("$argon2i$", "Argon2i"),
    ("$argon2d$", "Argon2d"),
    ("$argon2id$", "Argon2id"),
    
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

#----------------------------------------------------------------------------------

HEX_CHARSET: frozenset[str] = frozenset("0123456789abcdefABCDEF")

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

#----------------------------------------------------------------------------------

def _is_hex(text:str) -> bool:
    return bool(text) and all(c in HEX_CHARSET for c in text)

#----------------------------------------------------------------------------------

UPPER_CHARSET: frozenset[str] = frozenset("0123456789ABCDEF")
_MYSQL5_HEX_LENGTH = 40
_MYSQL5_TOTAL_LENGTH = _MYSQL5_HEX_LENGTH + 1

def _is_mysql5(text:str) -> bool:
    if len(text) != _MYSQL5_TOTAL_LENGTH or not text.startswith("*"):
        return False
    
    body = text[1:]
    return all(c in UPPER_CHARSET for c in body)

#----------------------------------------------------------------------------------

_DES_CRYPT_CHARSET: frozenset[str] = frozenset(
    "./0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
)
_DES_CRYPT_TOTAL_LENGTH = 13

def _is_des_crypt(text:str) -> bool:
    if len(text) != _DES_CRYPT_TOTAL_LENGTH:
        return False
    
    return all(c in _DES_CRYPT_CHARSET for c in text)

#----------------------------------------------------------------------------------

def identification(input:str) -> list[Candidates]:
    text = input.strip()
    
    if not text:
        return []
    
    for prefix, algorithm in PREFIX_RULES:
        if text.startswith(prefix):
            return [Candidates(algorithm = algorithm, confidence = "High")]

    if _is_mysql5(text):
        return[Candidates(algorithm = "MYSQL5", confidence = "High")]
    
    if _is_des_crypt(text):
        return[Candidates(algorithm = "DES crypt", confidence="Medium")]
    
    if _is_hex(text):
        algorithms = HEX_LENGTHS.get(len(text), [])
        candidates: list[Candidates] = []
        for i, algorithm in enumerate(algorithms):
            confidence: Confidence = "Medium" if i == 0 else "Low"
            candidates.append(
                Candidates(algorithm = algorithm, confidence = confidence)
            )
        return candidates
    
    if text.startswith("$"):
        rest = text[1:]
        if "$" in rest:
            algo = rest.split("$", 1)[0]
            if algo and all(c.isalnum() or c in "-_" for c in algo):
                return [
                    Candidates(
                        algorithm = f"PHC String ({algo})",
                        confidence = "Low"
                        )
                ]
    
    return []


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog = "hashid",
        description = (
            "Identify a hash string by prefix, length, and charset."
            "Returns candidates with confidence ratings."
        )
    )
    
    parser.add_argument(
        "hash",
        help = 
        "The hash string to identify - wrap in single quotes if it contains $."
    )
    
    parser.add_argument(
        "--top",
        "-n",
        type = int,
        default = 5,
        help = "Show at most this many candidates (default: 5)."
    )
    return parser


def _render_table(
    input:str,
    candidates: list[Candidates],
    console: Console
) -> None:
    table = Table(
        title = f"Candidates for: {input.strip()}",
        title_style = "blue",
        show_lines = False
    )
    
    table.add_column("Algorithm", style = "bold white", no_wrap = True)
    table.add_column("Confidence Rating", no_wrap = True)
    
    for candidate in candidates:
        table.add_row(candidate.algorithm, candidate.confidence)
    
    console.print(table)
    
def main() -> int:
    return 0

if __name__ == "__main__":
    sys.exit(main())