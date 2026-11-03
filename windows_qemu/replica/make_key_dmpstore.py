#!/usr/bin/env python3
"""Build a UEFI Shell `dmpstore -l` file that enrols a Secure Boot key store in a Setup Mode varstore.

    make_key_dmpstore.py ESL_DIR PK.key PK.crt KEK.key KEK.crt OUT_DIR

ESL_DIR holds PK.esl, KEK.esl, db.esl, dbx.esl (raw EFI_SIGNATURE_LISTs, e.g. sentinel-uefi/efivars/rev_97/, the
live board store). Each list is signed with efitools' sign-efi-sig-list into a time-based AUTH2 payload:
PK self-signed, KEK by PK, db and dbx by KEK (the same chain the board has). The dmpstore file holds KEK, db, dbx and
then PK, with attributes NV|BS|RT|TIME_BASED_AUTHENTICATED_WRITE_ACCESS (0x27). The shell passes each record's
attributes and data straight to gRT->SetVariable in file order (ShellPkg DmpStore.c LoadVariablesFromFile). In
Setup Mode Sentinel MM accepts KEK/db/dbx with any AUTH2 header and a self-signed PK, and the PK write moves the
store to User Mode, so PK must be last.

Writes OUT_DIR/{PK,KEK,db,dbx}.auth and OUT_DIR/sentinel-keys.dmp. The private keys are only read by sign-efi-sig-list
and never copied. Needs efitools and openssl.
"""
import struct, subprocess, sys, uuid, zlib
from pathlib import Path

GLOBAL = uuid.UUID("8be4df61-93ca-11d2-aa0d-00e098032b8c")
IMAGE_SECURITY = uuid.UUID("d719b2cb-3d3a-4596-a3bc-dad00e67656f")
ATTRS = 0x01 | 0x02 | 0x04 | 0x20      # NV | BS | RT | TIME_BASED_AUTHENTICATED_WRITE_ACCESS
ORDER = (("KEK", GLOBAL, "PK"), ("db", IMAGE_SECURITY, "KEK"), ("dbx", IMAGE_SECURITY, "KEK"), ("PK", GLOBAL, "PK"))


def pubkey(path: Path, kind: str) -> str:
    cmd = ["openssl", "x509", "-in", str(path), "-noout", "-pubkey"] if kind == "crt" else \
          ["openssl", "pkey", "-in", str(path), "-pubout"]
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


def record(name: str, guid: uuid.UUID, data: bytes) -> bytes:
    n = (name + "\0").encode("utf-16-le")
    body = struct.pack("<II", len(n), len(data)) + n + guid.bytes_le + struct.pack("<I", ATTRS) + data
    return body + struct.pack("<I", zlib.crc32(body) & 0xFFFFFFFF)


def main() -> int:
    if len(sys.argv) != 7:
        sys.exit(__doc__)
    esl_dir, pk_key, pk_crt, kek_key, kek_crt, out = (Path(a) for a in sys.argv[1:])
    signers = {"PK": (pk_key, pk_crt), "KEK": (kek_key, kek_crt)}
    for who, (k, c) in signers.items():
        if pubkey(k, "key") != pubkey(c, "crt"):
            sys.exit(f"{who}: {k} does not match {c}")
    pk_der = subprocess.run(["openssl", "x509", "-in", str(pk_crt), "-outform", "DER"], check=True,
                            capture_output=True).stdout
    if pk_der not in (esl_dir / "PK.esl").read_bytes():
        sys.exit(f"{esl_dir}/PK.esl does not hold {pk_crt}: the enrolled PK could not sign for itself")
    out.mkdir(parents=True, exist_ok=True)
    blob = b""
    for name, guid, signer in ORDER:
        key, crt = signers[signer]
        auth = out / f"{name}.auth"
        subprocess.run(["sign-efi-sig-list", "-k", str(key), "-c", str(crt), name, str(esl_dir / f"{name}.esl"),
                        str(auth)], check=True, capture_output=True)
        data = auth.read_bytes()
        esl = (esl_dir / f"{name}.esl").read_bytes()
        if not data.endswith(esl):
            sys.exit(f"{auth} does not end with {name}.esl")
        blob += record(name, guid, data)
        print(f"  {name:4} {len(esl):6} B list, {len(data) - len(esl)} B AUTH2, signed by {signer}")
    (out / "sentinel-keys.dmp").write_bytes(blob)
    print(f"wrote {out / 'sentinel-keys.dmp'} ({len(blob)} B; order KEK, db, dbx, PK)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
