from unittest.mock import MagicMock, patch


@patch("keepassxc_dbus_mcp.mcp_server.get_service")
@patch("keepassxc_dbus_mcp.mcp_server.subprocess.check_call")
def test_create_keypair_generates_and_stores(mock_call, get_service):
    # Arrange: fake ssh-keygen writes files referenced by -f path
    def _fake_check_call(args, stdout=None, stderr=None):
        f_index = args.index("-f") + 1
        base = args[f_index]
        with open(base, "w", encoding="utf-8") as f:
            f.write("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n")
        with open(base + ".pub", "w", encoding="utf-8") as f:
            # Use valid base64 so our simplified fingerprint logic works
            f.write("ssh-ed25519 AAAA email@example.com\n")
        return 0

    mock_call.side_effect = _fake_check_call

    svc = MagicMock()
    svc.create_credential.side_effect = ["/p/priv", "/p/meta"]
    get_service.return_value = svc

    from keepassxc_dbus_mcp.mcp_server import create_keypair, CreateKeypairRequest

    out = create_keypair(CreateKeypairRequest(label="My Key", email="email@example.com", generate_passphrase=True))
    assert isinstance(out, dict) and out["private_path"] == "/p/priv" and out["meta_path"] == "/p/meta"
    assert out["fingerprint"].startswith("SHA256:")
    # Verify attributes on meta include public key
    meta_attrs = svc.create_credential.call_args_list[1][0][2]
    assert meta_attrs["Aggregate"] == "ssh-keypair" and meta_attrs["Part"] == "meta"
    assert meta_attrs["PublicKeyOpenSSH"].startswith("ssh-ed25519 AAAA")


@patch("keepassxc_dbus_mcp.mcp_server.get_service")
def test_save_keypair_create_and_update(get_service):
    svc = MagicMock()
    # Create path returns
    svc.create_credential.side_effect = ["/p/a", "/p/b"]
    # Search returns pair when updating
    svc.search_credentials.return_value = [
        {"path": "/p/a", "label": "L", "attributes": {"Part": "private"}},
        {"path": "/p/b", "label": "L", "attributes": {"Part": "meta"}},
    ]
    svc.get_credential_attributes.side_effect = [
        {"Aggregate": "ssh-keypair", "Part": "private"},
        {"Aggregate": "ssh-keypair", "Part": "meta"},
    ]
    get_service.return_value = svc

    from keepassxc_dbus_mcp.mcp_server import save_keypair, SaveKeypairRequest

    # Create new
    req_new = SaveKeypairRequest(label="K", email="e@x", private_key_pem="PRIV", public_key_ssh="ssh-ed25519 AAAA e@x", passphrase="pp")
    out_new = save_keypair(req_new)
    assert isinstance(out_new, dict) and out_new["private_path"] == "/p/a" and out_new["meta_path"] == "/p/b"

    # Update existing
    req_upd = SaveKeypairRequest(keypair_id="abc", label="K2", email="e@x", private_key_pem="PRIV2", public_key_ssh="ssh-ed25519 AAAA e@x", passphrase="pp2")
    out_upd = save_keypair(req_upd)
    assert hasattr(out_upd, "keys")
    # Ensure edit_credential called for both items
    assert svc.edit_credential.call_count >= 2


@patch("keepassxc_dbus_mcp.mcp_server.get_service")
def test_retrieve_keypair_by_keypair_id(get_service):
    svc = MagicMock()
    # find by id
    svc.search_credentials.return_value = [
        {"path": "/p/priv", "label": "L", "attributes": {"Part": "private"}},
        {"path": "/p/meta", "label": "L", "attributes": {"Part": "meta"}},
    ]
    svc.get_credential_attributes.side_effect = [
        {"Aggregate": "ssh-keypair", "KeypairID": "abc", "Part": "private", "Email": "e@x", "Fingerprint": "SHA256:F"},
        {"Aggregate": "ssh-keypair", "KeypairID": "abc", "Part": "meta", "PublicKeyOpenSSH": "ssh-ed25519 AAAA e@x"},
    ]
    svc.get_credential_secret_as_temp_file.side_effect = ["/tmp/priv", "/tmp/pass"]
    get_service.return_value = svc

    from keepassxc_dbus_mcp.mcp_server import retrieve_keypair, RetrieveKeypairRequest

    out = retrieve_keypair(RetrieveKeypairRequest(keypair_id="abc", include_passphrase=True))
    assert out["private_key_temp_file"] == "/tmp/priv" and out["passphrase_temp_file"] == "/tmp/pass"
    assert out["public_key_ssh"].startswith("ssh-ed25519 AAAA")


@patch("keepassxc_dbus_mcp.mcp_server.get_service")
def test_list_keypairs_minimal_fields(get_service):
    svc = MagicMock()
    svc.search_credentials.return_value = [
        # Pair 1: private and meta
        {"path": "/p/1a", "label": "L1", "attributes": {"Aggregate": "ssh-keypair", "KeypairID": "id1", "Part": "private", "Algorithm": "ed25519", "Email": "a@x", "Fingerprint": "SHA256:F1"}},
        {"path": "/p/1b", "label": "L1", "attributes": {"Aggregate": "ssh-keypair", "KeypairID": "id1", "Part": "meta", "PublicKeyOpenSSH": "ssh-ed25519 AAAA a@x"}},
        # Pair 2: only meta present with Email via UserName
        {"path": "/p/2b", "label": "L2", "attributes": {"Aggregate": "ssh-keypair", "KeypairID": "id2", "Part": "meta", "Algorithm": "ed25519", "UserName": "b@x", "Fingerprint": "SHA256:F2"}},
    ]
    get_service.return_value = svc

    from keepassxc_dbus_mcp.mcp_server import list_keypairs

    out = list_keypairs()
    assert isinstance(out, list) and len(out) == 2
    # Ensure fields present
    for row in out:
        assert set(row.keys()) == {"keypair_id", "label", "type", "email", "sha"}
    # Verify one of them matches pair 1
    assert any(r["keypair_id"] == "id1" and r["label"] == "L1" and r["type"] == "ed25519" and r["email"] == "a@x" and r["sha"].startswith("SHA256:") for r in out)


@patch("keepassxc_dbus_mcp.mcp_server.get_service")
def test_delete_keypair_deletes_both(get_service):
    svc = MagicMock()
    # Resolve pair by KeypairID via search
    svc.search_credentials.return_value = [
        {"path": "/p/priv", "label": "L", "attributes": {"Aggregate": "ssh-keypair", "KeypairID": "id1", "Part": "private"}},
        {"path": "/p/meta", "label": "L", "attributes": {"Aggregate": "ssh-keypair", "KeypairID": "id1", "Part": "meta"}},
    ]
    # Direct helper used by delete_keypair does not search; stub helper paths via _find_pair_by_keypair_id behaviour
    # We simulate via get_service and then the function under test calls service.delete_credential on both paths
    get_service.return_value = svc
    # For robustness ensure our internal helper finds both; patch search to return both
    svc.delete_credential.side_effect = [True, True]

    from keepassxc_dbus_mcp.mcp_server import delete_keypair

    resp = delete_keypair("id1")
    assert hasattr(resp, "message")
    assert svc.delete_credential.call_count == 2


@patch("keepassxc_dbus_mcp.mcp_server.get_service")
def test_list_keypairs_fingerprint_fallback_from_pub(get_service):
    # No Fingerprint attribute present; should compute from PublicKeyOpenSSH
    svc = MagicMock()
    svc.search_credentials.return_value = [
        {"path": "/p/a", "label": "L", "attributes": {"Aggregate": "ssh-keypair", "KeypairID": "kid", "Part": "private", "Algorithm": "ed25519", "Email": "e@x"}},
        {"path": "/p/b", "label": "L", "attributes": {"Aggregate": "ssh-keypair", "KeypairID": "kid", "Part": "meta", "PublicKeyOpenSSH": "ssh-ed25519 AAAA e@x"}},
    ]
    get_service.return_value = svc

    from keepassxc_dbus_mcp.mcp_server import list_keypairs

    out = list_keypairs()
    assert isinstance(out, list) and len(out) == 1
    row = out[0]
    assert row["sha"].startswith("SHA256:") and len(row["sha"]) > len("SHA256:")


@patch("keepassxc_dbus_mcp.mcp_server.get_service")
def test_retrieve_keypair_fingerprint_fallback(get_service):
    # Neither item has Fingerprint; retrieve_keypair should compute from PublicKeyOpenSSH
    svc = MagicMock()
    svc.search_credentials.return_value = [
        {"path": "/p/priv", "label": "L", "attributes": {"Aggregate": "ssh-keypair", "KeypairID": "abc", "Part": "private"}},
        {"path": "/p/meta", "label": "L", "attributes": {"Aggregate": "ssh-keypair", "KeypairID": "abc", "Part": "meta"}},
    ]
    svc.get_credential_attributes.side_effect = [
        {"Aggregate": "ssh-keypair", "KeypairID": "abc", "Part": "private", "Email": "e@x"},
        {"Aggregate": "ssh-keypair", "KeypairID": "abc", "Part": "meta", "PublicKeyOpenSSH": "ssh-ed25519 AAAA e@x"},
    ]
    svc.get_credential_secret_as_temp_file.side_effect = ["/tmp/kk", "/tmp/pp"]
    get_service.return_value = svc

    from keepassxc_dbus_mcp.mcp_server import retrieve_keypair, RetrieveKeypairRequest

    out = retrieve_keypair(RetrieveKeypairRequest(keypair_id="abc"))
    assert out["fingerprint"].startswith("SHA256:") and len(out["fingerprint"]) > len("SHA256:")
