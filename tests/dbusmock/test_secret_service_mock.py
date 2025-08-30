import unittest
import pytest

dbus = pytest.importorskip("dbus")
DBusTestCase = pytest.importorskip("dbusmock").DBusTestCase


class TestSecretServiceWithDBusMock(DBusTestCase):
    """Headless D-Bus test using python-dbusmock to simulate a minimal
    org.freedesktop.secrets service with no collections.
    """

    def setUp(self):
        # Start an isolated session bus and set DBUS_SESSION_BUS_ADDRESS
        self.start_session_bus()
        # Spawn a mock Secret Service object. In python-dbusmock >= 0.30,
        # spawn_server returns only a Popen; obtain the object via the bus.
        self.p_mock = self.spawn_server(
            'org.freedesktop.secrets',
            '/org/freedesktop/secrets',
            'org.freedesktop.Secret.Service',
            system_bus=False,
        )

        # Obtain the mock object and ensure the Collections property exists
        # and is empty to simulate no collections present.
        bus = dbus.SessionBus()
        self.obj_service = bus.get_object(
            'org.freedesktop.secrets', '/org/freedesktop/secrets'
        )
        self.obj_service.AddProperties(
            'org.freedesktop.Secret.Service',
            {'Collections': dbus.Array([], signature='o')},
            dbus_interface='org.freedesktop.DBus.Mock'
        )

    def tearDown(self):
        # Stop the mock process
        self.p_mock.terminate()
        self.p_mock.wait()

    def test_list_credentials_on_empty_service(self):
        # With no collections, the list should be empty
        from keepassxc_dbus_mcp.credential_service import CredentialService

        svc = CredentialService()
        items = svc.list_credentials()
        self.assertEqual(items, [])


if __name__ == '__main__':
    unittest.main()
