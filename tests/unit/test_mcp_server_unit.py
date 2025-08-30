from unittest.mock import MagicMock, patch

import pytest


@patch("keepassxc_dbus_mcp.mcp_server.get_service")
def test_list_credentials_wraps_service(get_service):
    svc = MagicMock()
    svc.list_credentials.return_value = [
        {"path": "/p/1", "label": "L1", "attributes": {"a": 1}},
    ]
    get_service.return_value = svc

    from keepassxc_dbus_mcp.mcp_server import list_credentials

    result = list_credentials()
    assert isinstance(result, list)
    assert result[0]["label"] == "L1"


@patch("keepassxc_dbus_mcp.mcp_server.get_service")
def test_search_credentials_contains_match(get_service):
    svc = MagicMock()
    svc.list_credentials.return_value = [
        {"path": "/p/1", "label": "Alpha-ONE", "attributes": {"Title": "alpha-one"}},
        {"path": "/p/2", "label": "Beta", "attributes": {"Notes": "Contains ALPHA token"}},
    ]
    get_service.return_value = svc

    from keepassxc_dbus_mcp.mcp_server import search_credentials

    out = search_credentials("alpha one")
    paths = {x["path"] for x in out}
    # Phrase match after normalization should match the hyphenated label, not the second
    assert paths == {"/p/1"}


@patch("keepassxc_dbus_mcp.mcp_server.get_service")
def test_delete_credential_deletes(get_service):
    svc = MagicMock()
    svc.delete_credential.return_value = True
    get_service.return_value = svc

    from keepassxc_dbus_mcp.mcp_server import delete_credential

    resp = delete_credential("/org/freedesktop/secrets/x")
    assert hasattr(resp, "message")
    svc.delete_credential.assert_called_once()


@patch("keepassxc_dbus_mcp.mcp_server.get_service")
def test_get_secret_plaintext_gate(get_service):
    from importlib import reload
    import os
    import keepassxc_dbus_mcp.mcp_server as m

    # Ensure gate is enforced
    if "ALLOW_PLAINTEXT_SECRET" in os.environ:
        del os.environ["ALLOW_PLAINTEXT_SECRET"]
    reload(m)
    resp = m.get_credential_secret("/p")
    assert hasattr(resp, "error") and resp.status_code == 403


@patch("keepassxc_dbus_mcp.mcp_server.get_service")
def test_invalid_path_rejected_early(get_service):
    from keepassxc_dbus_mcp.mcp_server import get_credential_secret_as_temp_file

    resp = get_credential_secret_as_temp_file("not/a/real/path", timeout=10)
    assert hasattr(resp, "error") and resp.status_code == 400


@patch("keepassxc_dbus_mcp.mcp_server.get_service")
def test_timeout_validation(get_service):
    from keepassxc_dbus_mcp.mcp_server import get_credential_secret_as_temp_file

    # Good path prefix but bad timeout
    resp = get_credential_secret_as_temp_file("/org/freedesktop/secrets/whatever", timeout=0)
    assert hasattr(resp, "error") and resp.status_code == 400


@patch("keepassxc_dbus_mcp.mcp_server.get_service")
def test_label_validation_v2(get_service):
    svc = MagicMock()
    svc.create_credential.return_value = "/p/x"
    get_service.return_value = svc

    from keepassxc_dbus_mcp.mcp_server import create_credential, CreateCredentialRequest

    bad = create_credential(CreateCredentialRequest(label="bad\nlabel", password="pwd"))
    assert hasattr(bad, "error") and bad.status_code == 400

    ok = create_credential(CreateCredentialRequest(label="Good", password="pwd", attributes={"Title": "ignored", "k": "v"}))
    assert isinstance(ok, dict) and ok["path"] == "/p/x"
    called_attrs = svc.create_credential.call_args[0][2]
    assert called_attrs["Title"] == "Good"


@patch("keepassxc_dbus_mcp.mcp_server.get_service")
def test_create_uses_typed_fields_and_custom_attrs(get_service):
    svc = MagicMock()
    svc.create_credential.return_value = "/p/x"
    get_service.return_value = svc

    from keepassxc_dbus_mcp.mcp_server import create_credential, CreateCredentialRequest

    out = create_credential(CreateCredentialRequest(label="Demo", password="pwd", username="alice", url="https://x", notes="n", attributes={"custom": "v"}))
    assert isinstance(out, dict) and out["path"] == "/p/x"
    attrs = svc.create_credential.call_args[0][2]
    assert attrs["UserName"] == "alice"
    assert attrs["URL"] == "https://x"
    assert attrs["Notes"] == "n"
    assert attrs["custom"] == "v"


@patch("keepassxc_dbus_mcp.mcp_server.get_service")
def test_update_v2_uses_typed_fields(get_service):
    svc = MagicMock()
    get_service.return_value = svc

    from keepassxc_dbus_mcp.mcp_server import update_credential, UpdateCredentialRequest

    resp = update_credential(UpdateCredentialRequest(credential_path="/org/freedesktop/secrets/x", username="bob"))
    assert hasattr(resp, "message")
    called_attrs = svc.edit_credential.call_args[0][3]
    assert called_attrs == {"UserName": "bob"}


@patch("keepassxc_dbus_mcp.mcp_server.get_service")
def test_search_invalid_query(get_service):
    svc = MagicMock()
    svc.list_credentials.return_value = []
    get_service.return_value = svc

    from keepassxc_dbus_mcp.mcp_server import search_credentials

    # Only punctuation collapses to empty; expect empty list not error
    out = search_credentials("!!!")
    assert out == []


@patch("keepassxc_dbus_mcp.mcp_server.get_service")
def test_create_v2_typed_fields_merge(get_service):
    svc = MagicMock()
    svc.create_credential.return_value = "/p/new"
    get_service.return_value = svc

    from keepassxc_dbus_mcp.mcp_server import create_credential, CreateCredentialRequest

    req = CreateCredentialRequest(label="Demo", password="pwd", username="alice", url="https://x", notes="n", attributes={"k":"v"})
    out = create_credential(req)
    assert isinstance(out, dict) and out["path"] == "/p/new"
    attrs = svc.create_credential.call_args[0][2]
    assert attrs["Title"] == "Demo"
    assert attrs["UserName"] == "alice" and attrs["URL"] == "https://x" and attrs["Notes"] == "n"
    assert attrs["k"] == "v"


@patch("keepassxc_dbus_mcp.mcp_server.get_service")
def test_update_v2_typed_fields_merge(get_service):
    svc = MagicMock()
    get_service.return_value = svc

    from keepassxc_dbus_mcp.mcp_server import update_credential, UpdateCredentialRequest

    req = UpdateCredentialRequest(credential_path="/org/freedesktop/secrets/x", username="bob")
    resp = update_credential(req)
    assert hasattr(resp, "message")
    called_attrs = svc.edit_credential.call_args[0][3]
    assert called_attrs == {"UserName": "bob"}


    # Blob tools removed; no tests for blob storage/listing
