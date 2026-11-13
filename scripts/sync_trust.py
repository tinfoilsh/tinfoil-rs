#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["tuf>=5,<8", "cryptography>=43", "certifi>=2025.1.31"]
# ///
"""Regenerate the verifier's embedded trust material from its authoritative sources.

    uv run scripts/sync_trust.py [--allow-root-change]

Downloads the AMD Genoa and Turin certificate chains from the AMD KDS, the
Intel SGX Provisioning Certification Root CA from Intel, and the Sigstore
trusted root through a TUF client bootstrapped from a pinned root of the
Sigstore repository (SHA-256 below), then writes them under
``crates/verifier/src/trust/``: each anchor verbatim as a file in ``data/``,
and one generated Rust module per anchor that embeds the file and records
its source and SHA-256. The Tinfoil release signing key has no vendor
download; it is a hand-maintained constant in this script, pinned by its
SHA-256.

Every source is fetched and checked before anything is written, the files
are rendered into a temporary directory, and they replace the committed ones
only after every render succeeded, so a failure leaves the tree untouched.
Checks before writing:

- every download completes within the timeout and is non-empty;
- the bootstrap TUF root has the pinned SHA-256, and the trusted root is JSON
  with the expected media type and every authority kind present;
- each PEM holds exactly the expected certificates: the AMD chains the ASK
  then the ARK, with the ASK signed by the ARK and the ARK self-signed; the
  Intel file one self-signed root;
- the signing key has the pinned SHA-256 and loads as an ECDSA P-256 key;
- a self-signed root that differs from the committed one is refused unless
  ``--allow-root-change`` is passed, so a root never changes by accident. A
  committed bundle that holds no self-signed root at all is refused the same
  way: only a file that is truly absent starts from nothing. A committed
  file that cannot be read is an error, not a missing file;
- no path that is read or written passes through a symbolic link, in the
  file itself or in any directory between it and the repository root;
- every download is HTTPS from start to finish: a redirect to any other
  scheme is refused.

Installation is all or nothing: if replacing any file fails, the files
already replaced are put back and the new ones removed.

Running the script twice against unchanged sources produces identical files.

Dev tooling, not part of any published crate; the dependencies above are
resolved for this script alone.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import ssl
import sys
import tempfile
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import certifi
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from tuf.ngclient import Updater

REPO_ROOT = Path(__file__).resolve().parent.parent
TRUST_DIR = REPO_ROOT / "crates" / "verifier" / "src" / "trust"
DATA_DIR_NAME = "data"

TIMEOUT_SECONDS = 60

TRUSTED_ROOT_MEDIA_TYPE = "application/vnd.dev.sigstore.trustedroot+json;version=0.1"

AMD_GENOA_URL = "https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain"
AMD_TURIN_URL = "https://kdsintf.amd.com/vcek/v1/Turin/cert_chain"
INTEL_SGX_ROOT_URL = "https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem"

SIGSTORE_TUF_URL = "https://tuf-repo-cdn.sigstore.dev"
SIGSTORE_TUF_INITIAL_ROOT_URL = f"{SIGSTORE_TUF_URL}/5.root.json"
SIGSTORE_TUF_INITIAL_ROOT_SHA256 = "e2a930b2d1d4053dd56e8faf66fd113658545d522e35d222ccf58fea87ccccf4"
"""The root the TUF client is bootstrapped from; a different hash is a loud failure, never accepted.

Roots 1 to 3 of the Sigstore public-good repository carry expiry times with fractional seconds or a UTC offset,
which the TUF client rejects, and root 4 names its keys by a legacy key-id scheme that the client cannot match
against the signatures on root 5, so version 5 (the earliest from which the update chain verifies) is the pinned
starting point; the client then verifies every later root and the target against it.
"""
SIGSTORE_TRUSTED_ROOT_TARGET = "trusted_root.json"

# The Tinfoil release signing key authenticates registry issuers, public
# configs and artifact freshness approvals. It is published out of band, not
# downloadable, so it is maintained here by hand; rotating it means updating
# both the PEM and its SHA-256.
TINFOIL_SIGNING_KEY_PEM = """\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcadRPBdmNf1LPWYcY9AZ2Crrqxsy
nqzLE7k3kahjPxIM42bgZbze0GnT/EmGqe1w6So5AhmXci8By8Azt8gAhw==
-----END PUBLIC KEY-----
"""
TINFOIL_SIGNING_KEY_SHA256 = "7ff8acb6c54d0f969f53ba26ebef9200c3506bb9d45480b7d79be8170c1dbeb7"


class SyncError(Exception):
    """A source that cannot be used; nothing is written."""


@dataclass(frozen=True)
class Source:
    """Fetched bytes and where they came from, as recorded in the generated module header."""

    url: str
    content: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()


@dataclass(frozen=True)
class Anchor:
    """One embedded trust anchor: its source and the names it is written under."""

    source: Source
    module: str
    data_file: str
    constant: str
    doc: str
    certificates: bool = True
    """Whether the anchor is a PEM certificate bundle, whose self-signed roots are guarded against change."""


def require_https(url: str) -> None:
    if urllib.parse.urlsplit(url).scheme != "https":
        raise SyncError(f"{url}: refusing a URL that is not HTTPS")


class HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    """Follows a redirect only to another HTTPS URL, so that no hop of a download is unauthenticated."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201, PLR0913
        require_https(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url: str) -> Source:
    """Download ``url`` over HTTPS with a timeout; an empty body or any transport error is a SyncError."""
    require_https(url)
    # The interpreter that runs this script may have no system trust store; the
    # Mozilla bundle that certifi ships verifies the vendors' TLS certificates.
    context = ssl.create_default_context(cafile=certifi.where())
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), HttpsOnlyRedirects())
    try:
        with opener.open(url, timeout=TIMEOUT_SECONDS) as response:
            final_url = response.geturl()
            content = response.read()
    except OSError as err:
        raise SyncError(f"{url}: {err}") from err
    require_https(final_url)
    if not content:
        raise SyncError(f"{url}: empty response")
    return Source(url, content)


def fetch_sigstore_trusted_root(workdir: Path) -> Source:
    """Fetch ``trusted_root.json`` through a TUF client bootstrapped from the pinned initial root."""
    initial_root = fetch(SIGSTORE_TUF_INITIAL_ROOT_URL)
    if initial_root.sha256 != SIGSTORE_TUF_INITIAL_ROOT_SHA256:
        raise SyncError(
            f"{SIGSTORE_TUF_INITIAL_ROOT_URL}: SHA-256 {initial_root.sha256} does not match the pinned "
            f"{SIGSTORE_TUF_INITIAL_ROOT_SHA256}"
        )
    metadata_dir = workdir / "tuf-metadata"
    targets_dir = workdir / "tuf-targets"
    metadata_dir.mkdir()
    targets_dir.mkdir()
    try:
        updater = Updater(
            metadata_dir=str(metadata_dir),
            metadata_base_url=SIGSTORE_TUF_URL,
            target_dir=str(targets_dir),
            target_base_url=f"{SIGSTORE_TUF_URL}/targets",
            bootstrap=initial_root.content,
        )
        updater.refresh()
        info = updater.get_targetinfo(SIGSTORE_TRUSTED_ROOT_TARGET)
        if info is None:
            raise SyncError(f"TUF repository has no target {SIGSTORE_TRUSTED_ROOT_TARGET!r}")
        path = updater.download_target(info)
    except SyncError:
        raise
    except Exception as err:  # the TUF client raises its own hierarchy; every failure stops the sync
        raise SyncError(f"TUF update of {SIGSTORE_TRUSTED_ROOT_TARGET}: {err}") from err
    content = Path(path).read_bytes()
    if not content:
        raise SyncError(f"TUF target {SIGSTORE_TRUSTED_ROOT_TARGET} is empty")
    return Source(f"{SIGSTORE_TUF_URL} target {SIGSTORE_TRUSTED_ROOT_TARGET}", content)


def check_trusted_root(source: Source) -> None:
    try:
        root = json.loads(source.content.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as err:
        raise SyncError(f"{source.url}: not JSON: {err}") from err
    if not isinstance(root, dict) or root.get("mediaType") != TRUSTED_ROOT_MEDIA_TYPE:
        raise SyncError(f"{source.url}: not a Sigstore trusted root")
    for member in ("tlogs", "ctlogs", "certificateAuthorities", "timestampAuthorities"):
        if not root.get(member):
            raise SyncError(f"{source.url}: no {member}")


def load_certificates(what: str, pem: bytes, count: int | None) -> list[x509.Certificate]:
    try:
        certificates = x509.load_pem_x509_certificates(pem)
    except ValueError as err:
        raise SyncError(f"{what}: {err}") from err
    if count is not None and len(certificates) != count:
        raise SyncError(f"{what}: want {count} certificates, got {len(certificates)}")
    return certificates


def check_issued_by(subject: x509.Certificate, issuer: x509.Certificate, what: str) -> None:
    try:
        subject.verify_directly_issued_by(issuer)
    except (ValueError, TypeError, InvalidSignature) as err:
        raise SyncError(f"{what}: {err}") from err


def check_common_name(source: Source, certificate: x509.Certificate, want: str) -> None:
    cn = certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if len(cn) != 1 or cn[0].value != want:
        raise SyncError(f"{source.url}: want common name {want!r}")


def check_amd_chain(source: Source, product: str) -> None:
    ask, ark = load_certificates(source.url, source.content, 2)
    check_issued_by(ark, ark, f"{source.url}: ARK is not self-signed")
    check_issued_by(ask, ark, f"{source.url}: ASK is not signed by the ARK")
    check_common_name(source, ask, f"SEV-{product}")
    check_common_name(source, ark, f"ARK-{product}")


def check_intel_root(source: Source) -> None:
    (root,) = load_certificates(source.url, source.content, 1)
    check_issued_by(root, root, f"{source.url}: root is not self-signed")
    check_common_name(source, root, "Intel SGX Root CA")


def signing_key_source() -> Source:
    """The hand-maintained signing key, checked against its pin and loaded as an ECDSA P-256 key."""
    content = TINFOIL_SIGNING_KEY_PEM.encode("ascii")
    digest = hashlib.sha256(content).hexdigest()
    if digest != TINFOIL_SIGNING_KEY_SHA256:
        raise SyncError(f"signing key: SHA-256 {digest} does not match the pinned {TINFOIL_SIGNING_KEY_SHA256}")
    try:
        key = serialization.load_pem_public_key(content)
    except ValueError as err:
        raise SyncError(f"signing key: {err}") from err
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise SyncError("signing key is not ECDSA P-256")
    return Source("hand-maintained constant TINFOIL_SIGNING_KEY_PEM in scripts/sync_trust.py", content)


def self_signed_spkis(what: str, pem: bytes) -> set[bytes]:
    """The SPKIs of the self-signed certificates in a PEM bundle."""
    roots: set[bytes] = set()
    for certificate in load_certificates(what, pem, None):
        try:
            certificate.verify_directly_issued_by(certificate)
        except (ValueError, TypeError, InvalidSignature):
            continue
        roots.add(
            certificate.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    return roots


def refuse_symlinks(path: Path) -> None:
    """Refuse ``path`` if it, or any directory between it and the repository root, is a symbolic link.

    A link, dangling or not, is never what this script wrote; following or
    replacing one could read or clobber something outside the tree.
    """
    relative = path.relative_to(REPO_ROOT)
    current = REPO_ROOT
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise SyncError(f"{current}: is a symbolic link; refusing to read or write through it")


def committed_roots(path: Path) -> set[bytes] | None:
    """The SPKIs of the self-signed roots in a committed PEM file, or None if the file is truly absent."""
    refuse_symlinks(path)
    try:
        pem = path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as err:
        raise SyncError(f"{path}: cannot read the committed anchor: {err}") from err
    return self_signed_spkis(str(path), pem)


def check_root_change(path: Path, source: Source, allow: bool) -> None:
    before = committed_roots(path)
    if before is None or allow:
        return
    if not before:
        # An existing bundle without a root gives nothing to compare with;
        # treating it as absent would let any root in unnoticed.
        raise SyncError(
            f"{path.name}: the committed bundle holds no self-signed root; pass --allow-root-change to replace it"
        )
    if before != self_signed_spkis(source.url, source.content):
        raise SyncError(f"{path.name}: the self-signed root changed; pass --allow-root-change to accept it")


RUSTFMT_MAX_WIDTH = 100


def const_item(declaration: str, value: str) -> str:
    """A Rust constant laid out as rustfmt lays it out: on one line, or with the value on its own line."""
    one_line = f"{declaration} = {value};"
    if len(one_line) <= RUSTFMT_MAX_WIDTH:
        return one_line + "\n"
    return f"{declaration} =\n    {value};\n"


def render_module(anchor: Anchor) -> str:
    """The Rust module of one anchor: provenance in the header, the bytes embedded from the data file."""
    doc = "\n".join(f"/// {line}".rstrip() for line in anchor.doc.splitlines())
    return (
        "// Generated by scripts/sync_trust.py. Do not edit.\n"
        "//\n"
        f"// Source: {anchor.source.url}\n"
        f"// SHA-256: {anchor.source.sha256}\n"
        "\n"
        f"{doc}\n"
        + const_item(
            f"pub const {anchor.constant}: &[u8]", f'include_bytes!("{DATA_DIR_NAME}/{anchor.data_file}")'
        )
        + "\n"
        f"/// The SHA-256 of [`{anchor.constant}`], lowercase hex.\n"
        + const_item(f"pub const {anchor.constant}_SHA256: &str", f'"{anchor.source.sha256}"')
    )


def render_mod(anchors: list[Anchor]) -> str:
    """``mod.rs``: the module list and the re-exports."""
    lines = [
        "// Generated by scripts/sync_trust.py. Do not edit.",
        "",
        "//! The trust anchors that the verifier ships: constants generated from each",
        "//! publisher's own distribution, never fetched at run time.",
        "//!",
        "//! Each anchor is embedded byte for byte as its publisher serves it; the",
        "//! module that embeds it records the source and the SHA-256. Regenerate with",
        "//! `uv run scripts/sync_trust.py`.",
        "",
    ]
    lines += [f"mod {anchor.module};" for anchor in sorted(anchors, key=lambda a: a.module)]
    lines += ["", "#[cfg(test)]", "mod tests;", ""]
    for anchor in sorted(anchors, key=lambda a: a.module):
        lines.append(f"pub use {anchor.module}::{{{anchor.constant}, {anchor.constant}_SHA256}};")
    return "\n".join(lines) + "\n"


def render_all(workdir: Path, allow_root_change: bool) -> dict[str, bytes]:
    """Fetch and check every source; return the files to write, by path relative to the trust directory."""
    sigstore_root = fetch_sigstore_trusted_root(workdir)
    amd_genoa = fetch(AMD_GENOA_URL)
    amd_turin = fetch(AMD_TURIN_URL)
    intel_root = fetch(INTEL_SGX_ROOT_URL)
    signing_key = signing_key_source()

    check_trusted_root(sigstore_root)
    check_amd_chain(amd_genoa, "Genoa")
    check_amd_chain(amd_turin, "Turin")
    check_intel_root(intel_root)

    anchors = [
        Anchor(
            sigstore_root,
            "sigstore_root",
            "sigstore_trusted_root.json",
            "SIGSTORE_TRUSTED_ROOT_JSON",
            "The Sigstore trusted root: Fulcio, Rekor, CT log and timestamp authority\nmaterial, as JSON.",
            certificates=False,
        ),
        Anchor(
            amd_genoa,
            "amd_genoa",
            "amd_genoa_cert_chain.pem",
            "AMD_GENOA_CERT_CHAIN_PEM",
            "The AMD Genoa ASK and then ARK certificates, PEM.",
        ),
        Anchor(
            amd_turin,
            "amd_turin",
            "amd_turin_cert_chain.pem",
            "AMD_TURIN_CERT_CHAIN_PEM",
            "The AMD Turin ASK and then ARK certificates, PEM.",
        ),
        Anchor(
            intel_root,
            "intel_sgx_root",
            "intel_sgx_root_ca.pem",
            "INTEL_SGX_ROOT_CA_PEM",
            "The Intel SGX Provisioning Certification Root CA certificate, PEM.",
        ),
        Anchor(
            signing_key,
            "signing_keys",
            "tinfoil_signing_key.pem",
            "TINFOIL_SIGNING_KEY_PEM",
            "The public key that authenticates registry issuers, public configs and\n"
            "artifact freshness approvals, PEM.",
            certificates=False,
        ),
    ]

    data_dir = TRUST_DIR / DATA_DIR_NAME
    for anchor in anchors:
        if anchor.certificates:
            check_root_change(data_dir / anchor.data_file, anchor.source, allow_root_change)

    outputs: dict[str, bytes] = {"mod.rs": render_mod(anchors).encode("utf-8")}
    for anchor in anchors:
        outputs[f"{anchor.module}.rs"] = render_module(anchor).encode("utf-8")
        outputs[f"{DATA_DIR_NAME}/{anchor.data_file}"] = anchor.source.content
    return outputs


def install(staged: Path, backups: Path, outputs: dict[str, bytes]) -> None:
    """Replace the files of the trust directory with the staged ones, all or none.

    Nothing is written through a symbolic link. Every file that is about to
    be replaced is first copied to ``backups``; if any step fails, the files
    already replaced are restored from there and the files that did not exist
    before are removed, so that the tree is as it was.
    """
    for name in outputs:
        target = TRUST_DIR / name
        refuse_symlinks(target)
        if target.exists() and not target.is_file():
            raise SyncError(f"{target}: is not a regular file; refusing to replace it")

    replaced: list[str] = []
    created: list[Path] = []
    try:
        for name in outputs:
            target = TRUST_DIR / name
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                backup = backups / name
                backup.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(target, backup)
                replaced.append(name)
            else:
                created.append(target)
            shutil.move(staged / name, target)
    except OSError as err:
        # Put back everything, even if one file cannot be: a file that cannot
        # be restored is named, never silently left half written.
        unrestored: list[str] = []
        for restored in replaced:
            try:
                shutil.copy2(backups / restored, TRUST_DIR / restored)
            except OSError:
                unrestored.append(restored)
        for target in created:
            try:
                target.unlink(missing_ok=True)
            except OSError:
                unrestored.append(str(target.relative_to(TRUST_DIR)))
        outcome = (
            f"could not restore {', '.join(unrestored)}; check those files by hand"
            if unrestored
            else "the trust directory was restored"
        )
        raise SyncError(f"installing {name}: {err}; {outcome}") from err
    for name in outputs:
        print(f"wrote {(TRUST_DIR / name).relative_to(REPO_ROOT)}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--allow-root-change", action="store_true", help="accept a self-signed root that differs")
    args = parser.parse_args(argv)

    with tempfile.TemporaryDirectory(prefix="sync_trust-") as tmp:
        workdir = Path(tmp)
        try:
            outputs = render_all(workdir, args.allow_root_change)
            # Render everything into the temporary directory first; the committed
            # files are replaced only once every file is on disk.
            staged = workdir / "staged"
            for name, content in outputs.items():
                path = staged / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
            install(staged, workdir / "backups", outputs)
        except SyncError as err:
            print(f"sync_trust: {err}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
