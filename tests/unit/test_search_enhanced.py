from unittest.mock import MagicMock, patch


@patch("keepassxc_dbus_mcp.mcp_server.get_service")
def test_search_free_text_q_matches_keys_and_values(get_service):
    svc = MagicMock()
    svc.list_credentials.return_value = [
        {"path": "/p/1", "label": "L1", "attributes": {"Title": "X", "custom": "zzz"}},
        {"path": "/p/2", "label": "L2", "attributes": {"Title": "Y", "foo": "demo"}},
    ]
    get_service.return_value = svc

    from keepassxc_dbus_mcp.mcp_server import search_credentials

    out = search_credentials("demo")
    assert [x["path"] for x in out] == ["/p/2"]


@patch("keepassxc_dbus_mcp.mcp_server.get_service")
def test_search_contains_all_matches(get_service):
    svc = MagicMock()
    svc.list_credentials.return_value = [
        {"path": f"/p/{i}", "label": f"L{i}", "attributes": {"Title": f"T{i}"}}
        for i in range(6)
    ]
    get_service.return_value = svc

    from keepassxc_dbus_mcp.mcp_server import search_credentials

    results = search_credentials("L")
    assert [x["path"] for x in results] == [f"/p/{i}" for i in range(6)]


@patch("keepassxc_dbus_mcp.mcp_server.get_service")
def test_search_case_sensitivity(get_service):
    svc = MagicMock()
    svc.list_credentials.return_value = [
        {"path": "/p/1", "label": "Alpha", "attributes": {"Title": "Alpha"}},
        {"path": "/p/2", "label": "alpha", "attributes": {"Title": "alpha"}},
    ]
    get_service.return_value = svc

    from keepassxc_dbus_mcp.mcp_server import search_credentials

    # Case-insensitive matching should match both
    both = search_credentials("alpha")
    assert {x["path"] for x in both} == {"/p/1", "/p/2"}
