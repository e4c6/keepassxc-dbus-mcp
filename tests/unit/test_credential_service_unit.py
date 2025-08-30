import os
import tempfile
import time
from unittest.mock import MagicMock, patch

import pytest

from keepassxc_dbus_mcp.credential_service import CredentialService


@patch("keepassxc_dbus_mcp.credential_service.secretstorage")
def test_list_credentials_includes_label_path_attributes(mock_ss):
    mock_bus = object()
    mock_ss.dbus_init.return_value = mock_bus

    # Prepare fake collections/items
    item1 = MagicMock()
    item1.get_label.return_value = "Item One"
    item1.get_attributes.return_value = {"url": "https://a"}
    item1.item_path = "/org/1"

    item2 = MagicMock()
    item2.get_label.return_value = "Item Two"
    item2.get_attributes.return_value = {"url": "https://b"}
    item2.item_path = "/org/2"

    coll = MagicMock()
    coll.get_all_items.return_value = [item1, item2]
    mock_ss.get_all_collections.return_value = [coll]

    svc = CredentialService()
    items = svc.list_credentials()
    assert items == [
        {"label": "Item One", "attributes": {"url": "https://a"}, "path": "/org/1"},
        {"label": "Item Two", "attributes": {"url": "https://b"}, "path": "/org/2"},
    ]


@patch("keepassxc_dbus_mcp.credential_service.secretstorage")
def test_get_credential_secret_unlocked(mock_ss):
    mock_bus = object()
    mock_ss.dbus_init.return_value = mock_bus

    item = MagicMock()
    item.is_locked.return_value = False
    item.get_secret.return_value = b"s3cr3t"
    mock_ss.Item.return_value = item

    svc = CredentialService()
    secret = svc.get_credential_secret("/org/x")
    assert secret == "s3cr3t"


@patch("keepassxc_dbus_mcp.credential_service.secretstorage")
def test_get_credential_secret_locked_then_unlocks(mock_ss):
    mock_bus = object()
    mock_ss.dbus_init.return_value = mock_bus

    item = MagicMock()
    # First calls return True (locked), then False repeatedly
    item.is_locked.side_effect = [True, True, True, False, False]
    item.get_secret.return_value = b"token"
    mock_ss.Item.return_value = item

    svc = CredentialService()
    secret = svc.get_credential_secret("/org/y")
    assert secret == "token"
    assert item.unlock.called


@patch("keepassxc_dbus_mcp.credential_service.secretstorage")
def test_get_credential_secret_unlock_denied(mock_ss):
    mock_bus = object()
    mock_ss.dbus_init.return_value = mock_bus

    item = MagicMock()
    # Remains locked even after polling
    item.is_locked.return_value = True
    item.unlock.side_effect = Exception("dismissed")
    mock_ss.Item.return_value = item

    svc = CredentialService()
    assert svc.get_credential_secret("/org/z") is None


@patch("keepassxc_dbus_mcp.credential_service.secretstorage")
def test_get_credential_secret_as_temp_file_writes_and_deletes(mock_ss, tmp_path):
    mock_bus = object()
    mock_ss.dbus_init.return_value = mock_bus

    item = MagicMock()
    item.is_locked.return_value = False
    item.get_secret.return_value = b"abc123"
    mock_ss.Item.return_value = item

    svc = CredentialService()
    path = svc.get_credential_secret_as_temp_file("/org/ok", timeout=1)
    assert path is not None
    assert os.path.exists(path)
    with open(path, "r") as f:
        assert f.read() == "abc123"
    time.sleep(1.3)
    assert not os.path.exists(path)


@patch("keepassxc_dbus_mcp.credential_service.secretstorage")
def test_tempfile_prefers_shm_when_enabled(mock_ss, tmp_path, monkeypatch):
    mock_bus = object()
    mock_ss.dbus_init.return_value = mock_bus

    item = MagicMock()
    item.is_locked.return_value = False
    item.get_secret.return_value = b"xyz"
    mock_ss.Item.return_value = item

    # Enable SHM preference and make the checks pass
    monkeypatch.setenv("PREFER_SHM", "true")
    monkeypatch.setattr("os.path.isdir", lambda p: True)
    monkeypatch.setattr("os.access", lambda p, m: True)

    captured = {"dir": None}
    real_mkstemp = tempfile.mkstemp

    def fake_mkstemp(dir=None):
        captured["dir"] = dir
        # Create the file in tmp_path to avoid writing to real /dev/shm in tests
        return real_mkstemp(dir=str(tmp_path))

    monkeypatch.setattr(tempfile, "mkstemp", fake_mkstemp)

    svc = CredentialService()
    path = svc.get_credential_secret_as_temp_file("/org/shm")
    assert path is not None
    assert os.path.exists(path)
    with open(path, "r") as f:
        assert f.read() == "xyz"
    # Ensure our code attempted to use /dev/shm
    assert captured["dir"] == "/dev/shm"


@patch("keepassxc_dbus_mcp.credential_service.secretstorage")
def test_create_edit_delete_credential_flow(mock_ss):
    mock_bus = object()
    mock_ss.dbus_init.return_value = mock_bus

    # create
    collection = MagicMock()
    new_item = MagicMock()
    new_item.item_path = "/org/new"
    collection.create_item.return_value = new_item
    mock_ss.get_default_collection.return_value = collection

    svc = CredentialService()
    path = svc.create_credential("lbl", "pwd", {"k": "v"})
    assert path == "/org/new"

    # edit
    item = MagicMock()
    mock_ss.Item.return_value = item
    ok = svc.edit_credential(path, new_label="L2", new_password="P2", new_attributes={"x": "y"})
    assert ok is True
    item.set_label.assert_called_with("L2")
    item.set_secret.assert_called()
    item.set_attributes.assert_called_with({"x": "y"})

    # delete
    item_delete = MagicMock()
    mock_ss.Item.return_value = item_delete
    assert svc.delete_credential(path) is True
    item_delete.delete.assert_called()
