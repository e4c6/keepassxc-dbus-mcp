import sys
import os
import logging
from typing import Optional, Mapping
import uuid
import subprocess
import tempfile
import re


_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=getattr(logging, _level, logging.INFO), stream=sys.stderr)
logger = logging.getLogger(__name__)

# Highlight insecure mode if enabled
if os.getenv("ALLOW_PLAINTEXT_SECRET", "false").lower() == "true":
    logger.warning("ALLOW_PLAINTEXT_SECRET=true: plaintext secret retrieval enabled; use only in trusted scenarios.")

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field
from typing import Annotated

from .credential_service import CredentialService

# Lazily initialize the credential service so MCP handshake isn't blocked by
# environment-dependent setup (e.g., DBus). This helps Codex, which starts
# MCP servers with a minimal environment, complete `initialize` before any
# DBus access occurs.
_service_instance: Optional[CredentialService] = None
_service_init_error: Optional[str] = None

def get_service() -> CredentialService:
    global _service_instance
    global _service_init_error
    if _service_instance is None and _service_init_error is None:
        try:
            logger.debug("Creating CredentialService instance on first use…")
            _service_instance = CredentialService()
        except Exception as e:
            _service_init_error = f"CredentialService init failed: {e}"
            logger.exception(_service_init_error)
    if _service_instance is None:
        raise RuntimeError(_service_init_error or "CredentialService unavailable")
    return _service_instance

# Create an MCP server instance
mcp = FastMCP("KeePassXC Credential Helper")


# ---------- Models ----------

class CredentialItem(BaseModel):
    path: str
    label: str
    attributes: dict


class MessageResponse(BaseModel):
    message: str
    status_code: int = 200


class ErrorResponse(BaseModel):
    error: str
    status_code: int


# ---------- Typed request models ----------

class CreateCredentialRequest(BaseModel):
    label: Annotated[str, Field(..., description="Entry title")]
    password: Annotated[str, Field(..., description="Secret/password for the entry")]
    username: Annotated[Optional[str], Field(None, description="Username field")]
    url: Annotated[Optional[str], Field(None, description="URL field")]
    notes: Annotated[Optional[str], Field(None, description="Notes field")]
    # Optional additional attributes to add as custom fields
    attributes: Annotated[Optional[Mapping[str, str]], Field(None, description="Extra custom attributes (advanced)")]


class UpdateCredentialRequest(BaseModel):
    credential_path: Annotated[str, Field(..., description="Secret Service item path")]
    label: Annotated[Optional[str], Field(None, description="New Title")]
    password: Annotated[Optional[str], Field(None, description="New secret/password")]
    username: Annotated[Optional[str], Field(None, description="New Username (UserName)")]
    url: Annotated[Optional[str], Field(None, description="New URL")]
    notes: Annotated[Optional[str], Field(None, description="New Notes")]
    attributes: Annotated[Optional[Mapping[str, str]], Field(None, description="Additional attributes to set/update")]


# ---------- SSH keypair aggregate (two-item) models ----------

SSH_AGGREGATE = "ssh-keypair"
SSH_PART_PRIVATE = "private"
SSH_PART_META = "meta"


class CreateKeypairRequest(BaseModel):
    label: Annotated[str, Field(..., description="Human-friendly label for the keypair")]
    email: Annotated[str, Field(..., description="Email/comment to embed and to store as username")]
    passphrase: Annotated[Optional[str], Field(None, description="Key passphrase; leave empty for none")]
    generate_passphrase: Annotated[bool, Field(False, description="Generate a strong random passphrase")]
    algorithm: Annotated[str, Field("ed25519", description="Key algorithm; only 'ed25519' supported for now")]


class SaveKeypairRequest(BaseModel):
    # When provided, we update an existing pair; otherwise create new
    keypair_id: Annotated[Optional[str], Field(None, description="Aggregate KeypairID (UUID)")]
    label: Annotated[str, Field(..., description="Label for both items")]
    email: Annotated[str, Field(..., description="Username/email stored in UserName")]
    private_key_pem: Annotated[str, Field(..., description="Private key PEM (OpenSSH format)")]
    public_key_ssh: Annotated[str, Field(..., description="Public key (OpenSSH one-line)")]
    passphrase: Annotated[Optional[str], Field(None, description="Optional passphrase (stored as meta secret)")]
    algorithm: Annotated[str, Field("ed25519", description="Algorithm; only 'ed25519' supported")]


class RetrieveKeypairRequest(BaseModel):
    keypair_id: Annotated[Optional[str], Field(None, description="Aggregate KeypairID (UUID)")]
    # If provided, can be either private or meta item path; we will resolve the pair
    credential_path: Annotated[Optional[str], Field(None, description="Any item path belonging to the pair")]
    include_passphrase: Annotated[bool, Field(False, description="Include passphrase temp file if present")]

# ---------- Validation helpers ----------

CONTROL_CHARS_RE = re.compile(r"[\x00\r\n]")


def _valid_item_path(path: str) -> bool:
    if not isinstance(path, str):
        return False
    if CONTROL_CHARS_RE.search(path):
        return False
    # Basic allowlist: real items live under this prefix.
    if not path.startswith("/org/freedesktop/secrets/"):
        return False
    if len(path) > 512:
        return False
    return True


def _valid_label(label: Optional[str]) -> bool:
    if label is None:
        return True
    if not isinstance(label, str):
        return False
    if not (1 <= len(label) <= 256):
        return False
    if CONTROL_CHARS_RE.search(label):
        return False
    return True


def _sanitize_attributes(attrs: Optional[Mapping]) -> tuple[dict[str, str], Optional[str]]:
    """Ensure attributes is a small mapping of str->str without control chars.
    Returns (sanitized_attributes, error_message or None)
    """
    if attrs is None:
        return {}, None
    if not isinstance(attrs, Mapping):
        return {}, "attributes must be an object (mapping)"
    out: dict[str, str] = {}
    if len(attrs) > 64:
        return {}, "too many attributes (max 64)"
    for k, v in attrs.items():
        ks = str(k)
        vs = str(v)
        if len(ks) == 0 or len(ks) > 128:
            return {}, "attribute key too long"
        if len(vs) > 4096:
            return {}, "attribute value too long"
        if CONTROL_CHARS_RE.search(ks) or CONTROL_CHARS_RE.search(vs):
            return {}, "attributes contain control characters"
        out[ks] = vs
    return out, None


RESERVED_ATTRS = {
    "Title",
    "UserName",
    "URL",
    "Notes",
    "Aggregate",
    "Part",
    "KeypairID",
    "Algorithm",
    "Fingerprint",
    "Email",
    "PublicKeyOpenSSH",
}


def _filter_custom_attributes(attrs: dict[str, str]) -> dict[str, str]:
    """Drop reserved/canonical keys from custom attributes.

    Only custom keys are allowed via the attributes bag. Canonical fields
    must be set via typed parameters.
    """
    return {k: v for k, v in (attrs or {}).items() if k not in RESERVED_ATTRS}

# --- Define MCP Resources and Tools ---

@mcp.tool()
def list_credentials() -> list[dict]:
    """Returns a list of all credentials with path, label, attributes."""
    try:
        service = get_service()
    except Exception:
        return []
    credentials = service.list_credentials()
    return [CredentialItem(**c).model_dump() for c in credentials]

@mcp.tool()
def get_credential_detail(credential_path: str) -> dict | ErrorResponse:
    """Returns the public attributes of a specific credential."""
    if not _valid_item_path(credential_path):
        return ErrorResponse(error="Invalid credential_path", status_code=400)
    try:
        service = get_service()
    except Exception as e:
        return ErrorResponse(error=str(e), status_code=503)
    attributes = service.get_credential_attributes(credential_path)
    if attributes is not None:
        return attributes
    return ErrorResponse(error="Credential not found", status_code=404)

# (removed legacy update_credential)

@mcp.tool()
def get_credential_secret(credential_path: str) -> dict | ErrorResponse:
    """Retrieves the secret directly. Disabled unless ALLOW_PLAINTEXT_SECRET=true."""
    if os.getenv("ALLOW_PLAINTEXT_SECRET", "false").lower() != "true":
        return ErrorResponse(
            error="Direct secret retrieval is disabled. Use get_credential_secret_as_temp_file or set ALLOW_PLAINTEXT_SECRET=true.",
            status_code=403,
        )
    if not _valid_item_path(credential_path):
        return ErrorResponse(error="Invalid credential_path", status_code=400)
    logger.debug(f"Received credential path: {credential_path}")
    try:
        service = get_service()
    except Exception as e:
        return ErrorResponse(error=str(e), status_code=503)
    secret = service.get_credential_secret(credential_path)
    if secret is not None:
        return {"secret": secret}
    return ErrorResponse(error="Failed to retrieve secret. It may have been denied or not found.", status_code=403)

@mcp.tool()
def get_credential_secret_as_temp_file(
    credential_path: str,
    timeout: Annotated[int, Field(60, ge=1, le=3600, description="Seconds before the temporary file is deleted automatically.")],
) -> dict | ErrorResponse:
    """Retrieves a secret, writes it to a temp file, and schedules deletion."""
    logger.debug(f"Received request to save credential to temp file for path: {credential_path}")
    if not _valid_item_path(credential_path):
        return ErrorResponse(error="Invalid credential_path", status_code=400)
    if not isinstance(timeout, int) or timeout < 1 or timeout > 3600:
        return ErrorResponse(error="Invalid timeout (1-3600 seconds)", status_code=400)
    try:
        service = get_service()
    except Exception as e:
        return ErrorResponse(error=str(e), status_code=503)
    temp_file_path = service.get_credential_secret_as_temp_file(credential_path, timeout)
    if temp_file_path:
        return {"temp_file_path": temp_file_path}
    return ErrorResponse(error="Failed to retrieve secret or write to temp file.", status_code=403)

# (removed legacy create_credential)


@mcp.tool()
def create_credential(req: CreateCredentialRequest) -> dict | ErrorResponse:
    """Create a new credential (typed input).

    Behavior:
    - Title is always set to `req.label` (overrides any `Title` in attributes).
    - Canonical keys in KeePassXC are case‑sensitive: `Title`, `UserName`, `URL`, `Notes`.
    - This tool accepts typed fields (`username`, `url`, `notes`) and also merges `req.attributes`.
    - Non‑canonical keys in `req.attributes` are stored as custom attributes (Advanced).
    - The secret is `req.password`; it is not stored in attributes.
    """
    if not _valid_label(req.label):
        return ErrorResponse(error="Invalid label", status_code=400)
    # Start from attributes provided (custom-only)
    base_attrs, err = _sanitize_attributes(req.attributes or {})
    if err:
        return ErrorResponse(error=f"Invalid attributes: {err}", status_code=400)
    base_attrs = _filter_custom_attributes(base_attrs)
    # Merge typed convenience fields
    if req.username is not None:
        base_attrs["UserName"] = str(req.username)
    if req.url is not None:
        base_attrs["URL"] = str(req.url)
    if req.notes is not None:
        base_attrs["Notes"] = str(req.notes)

    attrs = dict(base_attrs)
    attrs["Title"] = req.label
    try:
        service = get_service()
    except Exception as e:
        return ErrorResponse(error=str(e), status_code=503)
    item_path = service.create_credential(req.label, req.password, attrs)
    return {"message": "Credential created successfully", "path": item_path, "status_code": 201}


@mcp.tool()
def search_credentials(q: str) -> list[dict] | ErrorResponse:
    """Search credentials by simple case-insensitive "contains" across public fields.

    Matches when the normalized query is a substring of any concatenated
    public fields: label, path, Title, UserName, URL, Notes, and all custom
    attribute keys and values.
    """
    try:
        service = get_service()
    except Exception as e:
        return ErrorResponse(error=str(e), status_code=503)

    if not isinstance(q, str):
        return ErrorResponse(error="Invalid query", status_code=400)

    import unicodedata

    def _normalize(text: str) -> str:
        if not isinstance(text, str):
            text = str(text)
        # Unicode normalize + ASCII fold + casefold
        t = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii").casefold()
        # Replace non-alphanumeric with spaces and collapse
        t = re.sub(r"[^a-z0-9]+", " ", t).strip()
        return t

    needle = _normalize(q)
    if len(needle) == 0:
        # Query reduced to nothing (e.g., only punctuation); return empty list
        return []

    items = service.list_credentials()

    def _hay(item: dict) -> str:
        attrs = item.get("attributes") or {}
        fields = [
            str(item.get("label", "")),
            str(item.get("path", "")),
            str(attrs.get("Title", "")),
            str(attrs.get("UserName", "")),
            str(attrs.get("URL", "")),
            str(attrs.get("Notes", "")),
        ] + [str(k) for k in attrs.keys()] + [str(v) for v in attrs.values()]
        return _normalize(" ".join(fields))

    filtered = [it for it in items if needle in _hay(it)]
    return [CredentialItem(**x).model_dump() for x in filtered]


@mcp.tool()
def delete_credential(credential_path: str) -> MessageResponse | ErrorResponse:
    """Delete a credential item by path."""
    if not _valid_item_path(credential_path):
        return ErrorResponse(error="Invalid credential_path", status_code=400)
    try:
        service = get_service()
    except Exception as e:
        return ErrorResponse(error=str(e), status_code=503)
    ok = service.delete_credential(credential_path)
    if ok:
        return MessageResponse(message="Credential deleted.")
    return ErrorResponse(error="Credential not found or deletion failed.", status_code=404)


@mcp.tool()
def update_credential(req: UpdateCredentialRequest) -> MessageResponse | ErrorResponse:
    """Update an existing credential using typed input.

    Behavior:
    - If `label` is provided, Title is set to that label.
    - If `password` is provided, it replaces the secret.
    - Merges typed fields (`username`, `url`, `notes`) and any `attributes` into canonical/custom attributes.
    - Does not delete unspecified attributes.
    """
    if not _valid_item_path(req.credential_path):
        return ErrorResponse(error="Invalid credential_path", status_code=400)
    if not _valid_label(req.label):
        return ErrorResponse(error="Invalid label", status_code=400)

    base_attrs, err = _sanitize_attributes(req.attributes or {})
    if err:
        return ErrorResponse(error=f"Invalid attributes: {err}", status_code=400)
    base_attrs = _filter_custom_attributes(base_attrs)
    if req.username is not None:
        base_attrs["UserName"] = str(req.username)
    if req.url is not None:
        base_attrs["URL"] = str(req.url)
    if req.notes is not None:
        base_attrs["Notes"] = str(req.notes)

    canon_attrs = base_attrs if base_attrs else None
    try:
        service = get_service()
    except Exception as e:
        return ErrorResponse(error=str(e), status_code=503)
    ok = service.edit_credential(req.credential_path, req.label, req.password, canon_attrs or None)
    if ok:
        return MessageResponse(message="Credential updated successfully.")
    return ErrorResponse(error="Credential not found or update failed.", status_code=404)


# (Blob tools removed: ATTACH:: attribute helpers are no longer exposed)


# ---------- SSH keypair aggregate tools ----------

def _gen_passphrase() -> str:
    import secrets
    # 32 bytes urlsafe ~ 256 bits entropy pre-encoding; good for passphrases
    return secrets.token_urlsafe(32)


def _fingerprint_from_pub_line(pub_line: str) -> str:
    """Compute an OpenSSH-style SHA256 fingerprint from a public key line.

    The expected format is "<type> <base64> [comment]". We compute
    base64(SHA256(raw_key)) without padding and prefix with "SHA256:".
    Returns empty string on failure.
    """
    try:
        parts = (pub_line or "").strip().split()
        if len(parts) < 2:
            return ""
        import hashlib, base64 as _b64
        # Pad base64 if needed for decoding
        b64_raw = parts[1]
        pad = (-len(b64_raw)) % 4
        raw = _b64.b64decode(b64_raw + ("=" * pad))
        digest = hashlib.sha256(raw).digest()
        b64 = _b64.b64encode(digest).decode("ascii").rstrip("=")
        return f"SHA256:{b64}"
    except Exception:
        return ""


# Legacy ssh-keygen fingerprint helper removed in simplified v2


def _merge_attributes(existing: dict, updates: dict) -> dict:
    """Shallow merge for attributes, preserving existing keys unless overridden."""
    out = dict(existing or {})
    out.update({k: v for k, v in updates.items() if v is not None})
    return out


def _build_common_attrs(label: str, email: str, algorithm: str, keypair_id: str, fingerprint: str) -> dict:
    return {
        "Title": label,
        "UserName": email,
        "Aggregate": SSH_AGGREGATE,
        "KeypairID": keypair_id,
        "Algorithm": algorithm,
        "Fingerprint": fingerprint,
        "Email": email,
    }


@mcp.tool()
def create_keypair(req: CreateKeypairRequest) -> dict | ErrorResponse:
    """Generate and store an SSH keypair as a two-item aggregate.

    Storage:
    - Private item: secret=private key; attributes include Aggregate=ssh-keypair, Part=private, KeypairID=UUID.
    - Meta item: secret=passphrase (optional); attributes include Part=meta and PublicKeyOpenSSH.
    - UserName is set to email; Title set to label on both.
    """
    if not _valid_label(req.label):
        return ErrorResponse(error="Invalid label", status_code=400)
    if not isinstance(req.email, str) or CONTROL_CHARS_RE.search(req.email) or len(req.email) < 1:
        return ErrorResponse(error="Invalid email", status_code=400)
    algorithm = (req.algorithm or "ed25519").lower()
    if algorithm != "ed25519":
        return ErrorResponse(error="Only ed25519 supported currently", status_code=400)

    # Passphrase handling
    if req.passphrase and req.generate_passphrase:
        return ErrorResponse(error="Provide either passphrase or set generate_passphrase, not both", status_code=400)
    passphrase = req.passphrase or ( _gen_passphrase() if req.generate_passphrase else "")

    # Generate with ssh-keygen to avoid new deps
    try:
        with tempfile.TemporaryDirectory() as tmp:
            key_base = f"{tmp}/id_ed25519"
            subprocess.check_call([
                "ssh-keygen", "-t", "ed25519", "-C", req.email, "-N", passphrase, "-f", key_base
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            with open(key_base, "r", encoding="utf-8") as f:
                priv_key = f.read()
            with open(key_base + ".pub", "r", encoding="utf-8") as f:
                pub_key = f.read().strip()
    except FileNotFoundError:
        return ErrorResponse(error="ssh-keygen not available on host", status_code=500)
    except subprocess.CalledProcessError:
        return ErrorResponse(error="ssh-keygen failed to create keypair", status_code=500)

    fingerprint = _fingerprint_from_pub_line(pub_key)
    kp_id = str(uuid.uuid4())

    # Prepare attributes
    common = _build_common_attrs(req.label, req.email, algorithm, kp_id, fingerprint)
    attrs_priv = dict(common)
    attrs_priv["Part"] = SSH_PART_PRIVATE
    attrs_meta = dict(common)
    attrs_meta["Part"] = SSH_PART_META
    attrs_meta["PublicKeyOpenSSH"] = pub_key
    # Public key is kept in clear as attribute for easy retrieval

    try:
        service = get_service()
    except Exception as e:
        return ErrorResponse(error=str(e), status_code=503)

    # Create both entries; if meta creation fails after private, we leave both created (best effort)
    private_path = service.create_credential(req.label, priv_key, attrs_priv)
    meta_path = service.create_credential(req.label, passphrase, attrs_meta)
    return {
        "message": "SSH keypair created successfully",
        "status_code": 201,
        "keypair_id": kp_id,
        "private_path": private_path,
        "meta_path": meta_path,
        "public_key_ssh": pub_key,
        "fingerprint": fingerprint,
    }


def _find_pair_by_keypair_id(service: CredentialService, keypair_id: str) -> tuple[Optional[str], Optional[str]]:
    results = service.search_credentials({
        "Aggregate": SSH_AGGREGATE,
        "KeypairID": keypair_id,
    })
    priv, meta = None, None
    for it in results:
        part = (it.get("attributes", {}) or {}).get("Part")
        if part == SSH_PART_PRIVATE:
            priv = it.get("path")
        elif part == SSH_PART_META:
            meta = it.get("path")
    return priv, meta


def _resolve_keypair_id_from_path(service: CredentialService, path: str) -> Optional[str]:
    attrs = service.get_credential_attributes(path)
    if not attrs or attrs.get("Aggregate") != SSH_AGGREGATE:
        return None
    return attrs.get("KeypairID")


@mcp.tool()
def save_keypair(req: SaveKeypairRequest) -> dict | ErrorResponse:
    """Create or update an SSH keypair aggregate.

    - When `keypair_id` is provided, find the existing pair; error if not found.
    - Otherwise, create a new pair using provided materials.
    - Public key goes to meta attributes, private key as private item secret.
    - Passphrase stored as meta secret (may be empty or None).
    """
    if not _valid_label(req.label):
        return ErrorResponse(error="Invalid label", status_code=400)
    if not isinstance(req.email, str) or CONTROL_CHARS_RE.search(req.email) or len(req.email) < 1:
        return ErrorResponse(error="Invalid email", status_code=400)
    algorithm = (req.algorithm or "ed25519").lower()
    if algorithm != "ed25519":
        return ErrorResponse(error="Only ed25519 supported", status_code=400)
    pub_line = req.public_key_ssh.strip()
    if not pub_line or " " not in pub_line:
        return ErrorResponse(error="Invalid public key format", status_code=400)

    try:
        service = get_service()
    except Exception as e:
        return ErrorResponse(error=str(e), status_code=503)

    kp_id = req.keypair_id or str(uuid.uuid4())
    priv_path, meta_path = None, None
    if req.keypair_id:
        priv_path, meta_path = _find_pair_by_keypair_id(service, req.keypair_id)
        if not priv_path or not meta_path:
            return ErrorResponse(error="keypair_id not found", status_code=404)

    # Compute fingerprint directly from the provided public key line
    fingerprint = _fingerprint_from_pub_line(pub_line) or ""

    common = _build_common_attrs(req.label, req.email, algorithm, kp_id, fingerprint)
    # Meta attributes
    attrs_meta = dict(common)
    attrs_meta["Part"] = SSH_PART_META
    attrs_meta["PublicKeyOpenSSH"] = pub_line
    # Public key stored on meta item
    # Private attributes
    attrs_priv = dict(common)
    attrs_priv["Part"] = SSH_PART_PRIVATE

    if priv_path and meta_path:
        # Update existing, merging attributes with current ones to avoid clobbering unrelated keys
        cur_priv = service.get_credential_attributes(priv_path) or {}
        cur_meta = service.get_credential_attributes(meta_path) or {}
        merged_priv = _merge_attributes(cur_priv, attrs_priv)
        merged_meta = _merge_attributes(cur_meta, attrs_meta)
        ok1 = service.edit_credential(priv_path, req.label, req.private_key_pem, merged_priv)
        ok2 = service.edit_credential(meta_path, req.label, req.passphrase or "", merged_meta)
        if not (ok1 and ok2):
            return ErrorResponse(error="Failed to update keypair", status_code=500)
    else:
        # Create new
        priv_path = service.create_credential(req.label, req.private_key_pem, attrs_priv)
        meta_path = service.create_credential(req.label, req.passphrase or "", attrs_meta)

    return {
        "message": "SSH keypair saved",
        "status_code": 201 if not req.keypair_id else 200,
        "keypair_id": kp_id,
        "private_path": priv_path,
        "meta_path": meta_path,
        "fingerprint": fingerprint,
        "public_key_ssh": pub_line,
    }


@mcp.tool()
def retrieve_keypair(req: RetrieveKeypairRequest) -> dict | ErrorResponse:
    """Retrieve an SSH keypair aggregate and return temp files for secrets.

    Select using `keypair_id` or any `credential_path` belonging to the pair.
    Returns paths for private key and (optionally) passphrase temp files.
    """
    try:
        service = get_service()
    except Exception as e:
        return ErrorResponse(error=str(e), status_code=503)

    kp_id = req.keypair_id
    if not kp_id and req.credential_path:
        if not _valid_item_path(req.credential_path):
            return ErrorResponse(error="Invalid credential_path", status_code=400)
        kp_id = _resolve_keypair_id_from_path(service, req.credential_path)
        if not kp_id:
            return ErrorResponse(error="Not an ssh-keypair item", status_code=404)
    if not kp_id:
        return ErrorResponse(error="Provide keypair_id or credential_path", status_code=400)

    priv_path, meta_path = _find_pair_by_keypair_id(service, kp_id)
    if not priv_path or not meta_path:
        return ErrorResponse(error="Keypair not found", status_code=404)

    # Gather attrs/meta
    priv_attrs = service.get_credential_attributes(priv_path) or {}
    meta_attrs = service.get_credential_attributes(meta_path) or {}
    pub_line = meta_attrs.get("PublicKeyOpenSSH", "")
    fingerprint = priv_attrs.get("Fingerprint") or meta_attrs.get("Fingerprint") or _fingerprint_from_pub_line(pub_line) or ""
    email = priv_attrs.get("Email") or meta_attrs.get("Email") or priv_attrs.get("UserName")

    # Secrets → temp files
    priv_tmp = service.get_credential_secret_as_temp_file(priv_path, 60)
    pass_tmp = None
    if req.include_passphrase:
        pass_tmp = service.get_credential_secret_as_temp_file(meta_path, 60)

    return {
        "keypair_id": kp_id,
        "private_path": priv_path,
        "meta_path": meta_path,
        "private_key_temp_file": priv_tmp,
        "passphrase_temp_file": pass_tmp,
        "public_key_ssh": pub_line,
        "fingerprint": fingerprint,
        "email": email,
    }


@mcp.tool()
def list_keypairs() -> list[dict] | ErrorResponse:
    """List stored SSH keypairs succinctly.

    Returns one entry per aggregate (KeypairID) with:
    - keypair_id: UUID of the pair
    - label: human-friendly label (prefers private item)
    - type: algorithm (e.g., ed25519)
    - email: stored email/username
    - sha: public fingerprint in standard format (e.g., SHA256:...)
    """
    try:
        service = get_service()
    except Exception as e:
        return ErrorResponse(error=str(e), status_code=503)

    items = service.search_credentials({"Aggregate": SSH_AGGREGATE})
    by_id: dict[str, dict] = {}
    for it in items:
        attrs = (it.get("attributes") or {})
        kp_id = attrs.get("KeypairID")
        if not kp_id:
            continue
        entry = by_id.setdefault(kp_id, {"keypair_id": kp_id, "label": "", "type": "", "email": "", "sha": ""})
        # Prefer values from private part; fall back to meta
        # Label: capture first seen; prefer private (by writing only if empty)
        lbl = it.get("label")
        if lbl and not entry["label"]:
            entry["label"] = str(lbl)
        algo = attrs.get("Algorithm")
        if algo and not entry["type"]:
            entry["type"] = str(algo)
        # Email might be under Email or UserName
        email = attrs.get("Email") or attrs.get("UserName")
        if email and not entry["email"]:
            entry["email"] = str(email)
        fpr = attrs.get("Fingerprint")
        if fpr and not entry["sha"]:
            entry["sha"] = str(fpr)
        # If still missing, compute from public key if present on meta
        if not entry["sha"]:
            pub = attrs.get("PublicKeyOpenSSH")
            if pub:
                fp2 = _fingerprint_from_pub_line(pub)
                if fp2:
                    entry["sha"] = fp2

    # Return stable ordering by email then keypair_id
    out = list(by_id.values())
    out.sort(key=lambda x: (x["email"], x["keypair_id"]))
    return out


@mcp.tool()
def delete_keypair(keypair_id: str) -> MessageResponse | ErrorResponse:
    """Delete both items of an SSH keypair aggregate."""
    if not isinstance(keypair_id, str) or CONTROL_CHARS_RE.search(keypair_id) or len(keypair_id) < 3:
        return ErrorResponse(error="Invalid keypair_id", status_code=400)
    try:
        service = get_service()
    except Exception as e:
        return ErrorResponse(error=str(e), status_code=503)
    priv_path, meta_path = _find_pair_by_keypair_id(service, keypair_id)
    if not priv_path or not meta_path:
        return ErrorResponse(error="Keypair not found", status_code=404)
    ok1 = service.delete_credential(priv_path)
    ok2 = service.delete_credential(meta_path)
    if ok1 and ok2:
        return MessageResponse(message="Keypair deleted")
    return ErrorResponse(error="Failed to delete one or more items", status_code=500)

def main() -> None:
    """Entry point to run the MCP stdio server.

    Note: Never print to stdout from this process. JSON-RPC uses stdout;
    all logging is configured to stderr.
    """
    import asyncio
    asyncio.run(mcp.run_stdio_async())


# --- Run the MCP Application ---
if __name__ == "__main__":
    main()
