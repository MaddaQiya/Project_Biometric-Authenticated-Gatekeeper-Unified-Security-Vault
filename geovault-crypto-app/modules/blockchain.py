"""
GeoVault - Local Blockchain Ledger for Critical Assets
======================================================

Each critical asset (secret coordinates, certificates, high-value records)
is recorded as an immutable block in the ``blockchain_ledger`` SQLite table.

Block structure
---------------
    index, timestamp, asset_name, encrypted_asset_metadata,
    previous_hash, nonce, current_hash

    current_hash = SHA-256( canonical_json(index, timestamp, asset_name,
                                           encrypted_asset_metadata,
                                           previous_hash, nonce) )

Proof-of-Work: ``nonce`` is incremented until ``current_hash`` starts with
``"00"`` (difficulty 2 -> ~256 attempts on average).

Defence in depth
----------------
1. **Hash chaining** - modifying any block changes its hash and breaks the
   ``previous_hash`` link of the next block.
2. **Proof-of-Work** - every block hash must satisfy the difficulty target.
3. **Authenticated encryption** - metadata is sealed with AES-256-GCM; the
   associated data binds the ciphertext to its ``index`` and ``asset_name``,
   so renaming or moving a block is detected even if it is re-mined.
4. **HMAC-signed tip anchor** - PoW with difficulty 2 is trivial to redo, so
   an attacker with DB access could re-mine the whole chain. The app stores
   ``HMAC-SHA256(K_anchor, last_index | last_hash)`` in ``app_meta``; without
   the master secret a re-mined, truncated or extended chain cannot produce a
   matching anchor.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

import config
import database

DIFFICULTY = config.POW_DIFFICULTY
HASH_PREFIX = "0" * DIFFICULTY
GENESIS_PREVIOUS_HASH = "0" * 64
GENESIS_ASSET_NAME = "GENESIS"
ANCHOR_META_KEY = "ledger_tip_anchor"
GCM_NONCE_BYTES = 12
GCM_TAG_BYTES = 16
MAX_NONCE = 2**32

ASSET_TYPES = ("Secret Coordinates", "Digital Certificate", "High-Value Record")


# --------------------------------------------------------------------------- #
# Block model
# --------------------------------------------------------------------------- #
@dataclass
class Block:
    index: int
    timestamp: str
    asset_name: str
    encrypted_asset_metadata: str
    previous_hash: str
    nonce: int = 0
    current_hash: str = ""

    def header_bytes(self) -> bytes:
        """Canonical, deterministic serialisation of every hashed field."""
        header = {
            "index": self.index,
            "timestamp": self.timestamp,
            "asset_name": self.asset_name,
            "encrypted_asset_metadata": self.encrypted_asset_metadata,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
        }
        return json.dumps(header, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def compute_hash(self) -> str:
        return SHA256.new(self.header_bytes()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Block":
        return cls(
            index=int(data["index"]),
            timestamp=str(data["timestamp"]),
            asset_name=str(data["asset_name"]),
            encrypted_asset_metadata=str(data["encrypted_asset_metadata"]),
            previous_hash=str(data["previous_hash"]),
            nonce=int(data["nonce"]),
            current_hash=str(data["current_hash"]),
        )


@dataclass
class MiningResult:
    block: Block
    attempts: int
    elapsed_ms: float


@dataclass
class VerificationIssue:
    index: int
    kind: str      # HASH_MISMATCH | POW_INVALID | BROKEN_LINK | INDEX_GAP | DECRYPTION_FAILED | ANCHOR_*
    detail: str


@dataclass
class VerificationReport:
    valid: bool
    blocks_checked: int
    issues: list[VerificationIssue] = field(default_factory=list)
    block_status: dict[int, str] = field(default_factory=dict)  # index -> "OK" | "TAMPERED"
    elapsed_ms: float = 0.0


# --------------------------------------------------------------------------- #
# Crypto helpers
# --------------------------------------------------------------------------- #
def _ledger_key() -> bytes:
    return config.derive_subkey(config.PURPOSE_LEDGER_AES, 32)  # AES-256


def _aad(index: int, asset_name: str) -> bytes:
    return f"GeoVault-ledger|{index}|{asset_name}".encode("utf-8")


def encrypt_metadata(metadata: dict[str, Any], index: int, asset_name: str) -> str:
    """AES-256-GCM encrypt metadata -> base64(nonce | tag | ciphertext)."""
    cipher = AES.new(_ledger_key(), AES.MODE_GCM, nonce=get_random_bytes(GCM_NONCE_BYTES), mac_len=GCM_TAG_BYTES)
    cipher.update(_aad(index, asset_name))
    plaintext = json.dumps(metadata, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode("ascii")


def decrypt_metadata(block: Block) -> dict[str, Any]:
    """Decrypt & authenticate a block's metadata. Raises ``ValueError`` on tampering."""
    try:
        raw = base64.b64decode(block.encrypted_asset_metadata, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Metadata is not valid base64: {exc}") from exc
    if len(raw) <= GCM_NONCE_BYTES + GCM_TAG_BYTES:
        raise ValueError("Metadata ciphertext is truncated.")
    nonce, tag = raw[:GCM_NONCE_BYTES], raw[GCM_NONCE_BYTES:GCM_NONCE_BYTES + GCM_TAG_BYTES]
    cipher = AES.new(_ledger_key(), AES.MODE_GCM, nonce=nonce, mac_len=GCM_TAG_BYTES)
    cipher.update(_aad(block.index, block.asset_name))
    plaintext = cipher.decrypt_and_verify(raw[GCM_NONCE_BYTES + GCM_TAG_BYTES:], tag)
    return json.loads(plaintext)


def compute_anchor(block: Block) -> str:
    """HMAC-SHA256 over the chain tip, keyed with a secret derived from the master key."""
    mac = HMAC.new(config.derive_subkey(config.PURPOSE_LEDGER_ANCHOR, 32), digestmod=SHA256)
    mac.update(f"{block.index}|{block.current_hash}".encode("ascii"))
    return mac.hexdigest()


# --------------------------------------------------------------------------- #
# Proof-of-Work
# --------------------------------------------------------------------------- #
def mine_block(block: Block, difficulty: int = DIFFICULTY) -> MiningResult:
    """Increment ``nonce`` until SHA-256(header) has ``difficulty`` leading zeros."""
    prefix = "0" * difficulty
    start = time.perf_counter()
    for nonce in range(MAX_NONCE):
        block.nonce = nonce
        digest = block.compute_hash()
        if digest.startswith(prefix):
            block.current_hash = digest
            return MiningResult(block, nonce + 1, (time.perf_counter() - start) * 1000)
    raise RuntimeError("Nonce space exhausted without satisfying the PoW target.")


# --------------------------------------------------------------------------- #
# Chain operations
# --------------------------------------------------------------------------- #
def get_chain() -> list[Block]:
    return [Block.from_dict(b) for b in database.get_all_blocks()]


def ensure_genesis() -> Optional[Block]:
    """Create the genesis block if the ledger is empty (race-safe)."""
    def builder(last: Optional[dict]):
        if last is not None:
            return None  # ledger already initialised
        meta = {"note": "GeoVault genesis block", "created_by": "system", "difficulty": DIFFICULTY}
        block = Block(
            index=0,
            timestamp=database.utc_now_iso(),
            asset_name=GENESIS_ASSET_NAME,
            encrypted_asset_metadata=encrypt_metadata(meta, 0, GENESIS_ASSET_NAME),
            previous_hash=GENESIS_PREVIOUS_HASH,
        )
        mine_block(block)
        return block.to_dict(), {ANCHOR_META_KEY: compute_anchor(block)}

    created = database.append_block_atomic(builder)
    return Block.from_dict(created) if created else None


def add_asset(asset_name: str, asset_type: str, metadata: dict[str, Any], owner: str) -> MiningResult:
    """
    Encrypt the asset metadata, mine a new block on top of the current tip and
    persist it together with a refreshed HMAC tip anchor - atomically.
    """
    asset_name = (asset_name or "").strip()
    if not 1 <= len(asset_name) <= 120:
        raise ValueError("Asset name must be between 1 and 120 characters.")
    if asset_type not in ASSET_TYPES:
        raise ValueError(f"Unknown asset type: {asset_type}")
    ensure_genesis()

    payload = {
        "asset_type": asset_type,
        "owner": owner,
        "recorded_at": database.utc_now_iso(),
        "data": metadata,
    }
    result: dict[str, MiningResult] = {}

    def builder(last: Optional[dict]):
        if last is None:
            raise RuntimeError("Genesis block missing - ledger not initialised.")
        index = int(last["index"]) + 1
        block = Block(
            index=index,
            timestamp=database.utc_now_iso(),
            asset_name=asset_name,
            encrypted_asset_metadata=encrypt_metadata(payload, index, asset_name),
            previous_hash=last["current_hash"],
        )
        result["mined"] = mine_block(block)
        return block.to_dict(), {ANCHOR_META_KEY: compute_anchor(block)}

    database.append_block_atomic(builder)
    return result["mined"]


def verify_chain(check_decryption: bool = True) -> VerificationReport:
    """
    Recalculate every hash and link in the ledger.

    Checks per block: index continuity, SHA-256 recomputation, PoW target,
    ``previous_hash`` linkage, AES-GCM tag of the metadata; finally the HMAC
    tip anchor is compared with the actual last block.
    """
    start = time.perf_counter()
    chain = get_chain()
    issues: list[VerificationIssue] = []

    if not chain:
        issues.append(VerificationIssue(-1, "EMPTY", "Ledger contains no blocks (genesis missing)."))

    for pos, block in enumerate(chain):
        if block.index != pos:
            issues.append(VerificationIssue(block.index, "INDEX_GAP",
                                            f"Expected index {pos}, found {block.index} (block deleted/reordered)."))
        recomputed = block.compute_hash()
        if recomputed != block.current_hash:
            issues.append(VerificationIssue(block.index, "HASH_MISMATCH",
                                            f"Stored {block.current_hash[:16]}… ≠ recomputed {recomputed[:16]}…"))
        if not block.current_hash.startswith(HASH_PREFIX):
            issues.append(VerificationIssue(block.index, "POW_INVALID",
                                            f"Hash does not satisfy difficulty '{HASH_PREFIX}'."))
        expected_prev = GENESIS_PREVIOUS_HASH if pos == 0 else chain[pos - 1].current_hash
        if block.previous_hash != expected_prev:
            issues.append(VerificationIssue(block.index, "BROKEN_LINK",
                                            "previous_hash does not match the preceding block's hash."))
        if check_decryption:
            try:
                decrypt_metadata(block)
            except (ValueError, KeyError) as exc:
                issues.append(VerificationIssue(block.index, "DECRYPTION_FAILED",
                                                f"AES-GCM authentication failed: {exc}"))

    if chain:
        stored_anchor = database.get_meta(ANCHOR_META_KEY)
        tip = chain[-1]
        if stored_anchor is None:
            issues.append(VerificationIssue(tip.index, "ANCHOR_MISSING", "HMAC tip anchor is missing."))
        else:
            mac = HMAC.new(config.derive_subkey(config.PURPOSE_LEDGER_ANCHOR, 32), digestmod=SHA256)
            mac.update(f"{tip.index}|{tip.current_hash}".encode("ascii"))
            try:
                mac.hexverify(stored_anchor)
            except ValueError:
                issues.append(VerificationIssue(
                    tip.index, "ANCHOR_MISMATCH",
                    "Chain tip does not match the HMAC-signed anchor (chain re-mined, truncated or extended)."))

    tampered = {i.index for i in issues}
    status = {b.index: ("TAMPERED" if b.index in tampered else "OK") for b in chain}
    return VerificationReport(
        valid=not issues,
        blocks_checked=len(chain),
        issues=issues,
        block_status=status,
        elapsed_ms=(time.perf_counter() - start) * 1000,
    )


def export_chain_json() -> str:
    """Export the raw (still encrypted) ledger as pretty JSON."""
    return json.dumps([b.to_dict() for b in get_chain()], indent=2, ensure_ascii=False)


# --------------------------------------------------------------------------- #
# Tamper Lab (demo only) - simulates an attacker with direct DB access
# --------------------------------------------------------------------------- #
TAMPER_MODES = {
    "edit_data": "Edit asset_name directly in SQLite (no re-mining)",
    "remine_chain": "Edit asset_name AND re-mine this + all following blocks (smart attacker)",
    "delete_block": "Delete the block row from SQLite",
}


def simulate_tampering(index: int, mode: str) -> str:
    """Corrupt the ledger on purpose so the integrity checker can be demonstrated."""
    chain = get_chain()
    target = next((b for b in chain if b.index == index), None)
    if target is None:
        raise ValueError(f"Block #{index} does not exist.")

    if mode == "edit_data":
        target.asset_name = f"{target.asset_name} [FORGED]"
        database.overwrite_block(target.to_dict())
        return f"Block #{index} asset_name modified without re-mining."

    if mode == "remine_chain":
        pos = chain.index(target)
        target.asset_name = f"{target.asset_name} [FORGED]"
        for i in range(pos, len(chain)):
            if i > 0:
                chain[i].previous_hash = chain[i - 1].current_hash
            mine_block(chain[i])
            database.overwrite_block(chain[i].to_dict())
        return f"Block #{index} forged and {len(chain) - pos} block(s) re-mined with valid PoW."

    if mode == "delete_block":
        database.delete_block(index)
        return f"Block #{index} deleted from the ledger."

    raise ValueError(f"Unknown tamper mode: {mode}")


def reset_ledger() -> None:
    """Wipe the ledger and start over with a new genesis block."""
    database.clear_ledger(meta_keys=(ANCHOR_META_KEY,))
    ensure_genesis()
