import os
import pytest
import secretstorage

from keepassxc_dbus_mcp.credential_service import CredentialService

# Skip this entire module unless explicitly enabled. These tests interact
# with a real Secret Service provider (KeePassXC) and may prompt the user.
pytestmark = pytest.mark.skipif(os.getenv("E2E") != "1", reason="E2E test requires running Secret Service and user approval")

# --- Test functions ---
def test_list():
    print("\n--- Testing list_credentials ---")
    service = CredentialService()
    credentials = service.list_credentials()
    if credentials:
        print(f"Found {len(credentials)} credentials.")
        for cred in credentials[:5]:  # Print first 5 for brevity
            label = cred.get('label', '<no-label>')
            print(f"  - Label: {label}, Path: {cred['path']}")
        return credentials[0]['path'] # Return a path for the next test
    else:
        print("No credentials found.")
        return None

def test_get_attributes(item_path: str):
    print("\n--- Testing get_credential_attributes ---")
    if not item_path:
        print("No item path provided, skipping test.")
        return
    service = CredentialService()
    attributes = service.get_credential_attributes(item_path)
    if attributes:
        print(f"Attributes for {item_path}:")
        print(attributes)
    else:
        print(f"Could not find attributes for {item_path}.")

def test_get_secret(item_path: str):
    print("\n--- Testing get_credential_secret ---")
    if not item_path:
        print("No item path provided, skipping test.")
        return
    print("Please be ready to approve the KeePassXC prompt.")
    service = CredentialService()
    secret = service.get_credential_secret(item_path)
    if secret:
        print(f"Successfully retrieved secret: {secret[:4]}... (truncated)")
    else:
        print("Failed to retrieve secret.")

def test_create_credential():
    print("\n--- Testing create_credential ---")
    service = CredentialService()
    label = "mcp-test-credential"
    password = "super-secret-password-123"
    attributes = {"app": "mcp-e4c6-test", "user": "test-user"}
    
    print(f"Attempting to create credential: {label}")
    item_path = service.create_credential(label, password, attributes)
    print(f"Credential created with path: {item_path}")

    try:
        # Verify creation
        print("Verifying creation...")
        retrieved_attrs = service.get_credential_attributes(item_path)
        print(f"Retrieved attributes: {retrieved_attrs}")
        assert retrieved_attrs['app'] == 'mcp-e4c6-test'
    finally:
        # Cleanup
        print("Cleaning up created credential...")
        item = secretstorage.Item(service.bus, item_path)
        item.delete()
        print("Credential deleted.")

def test_edit_credential():
    print("\n--- Testing edit_credential ---")
    service = CredentialService()
    label = "mcp-edit-test"
    password = "initial-password"
    attributes = {"app": "mcp-test", "status": "initial"}

    # 1. Create a dummy credential to edit
    item_path = service.create_credential(label, password, attributes)
    print(f"Created temporary credential for editing at: {item_path}")

    try:
        # 2. Edit the credential
        new_label = "mcp-edit-test-updated"
        new_password = "updated-password"
        new_attributes = {"app": "mcp-test", "status": "updated"}
        
        success = service.edit_credential(item_path, new_label, new_password, new_attributes)
        assert success, "Edit operation failed."
        print("Edit operation successful.")

        # 3. Verify the changes
        print("Verifying changes...")
        item = secretstorage.Item(service.bus, item_path)
        
        retrieved_label = item.get_label()
        print(f"Retrieved label: {retrieved_label}")
        assert retrieved_label == new_label

        retrieved_attrs = item.get_attributes()
        print(f"Retrieved attributes: {retrieved_attrs}")
        assert retrieved_attrs['status'] == 'updated'

        print("Verifying secret (unlock required)...")
        retrieved_secret = service.get_credential_secret(item_path)
        print(f"Retrieved secret: {retrieved_secret[:4]}...")
        assert retrieved_secret == new_password
        print("All edits verified successfully.")

    finally:
        # 4. Cleanup
        print("Cleaning up edited credential...")
        item = secretstorage.Item(service.bus, item_path)
        item.delete()
        print("Credential deleted.")


if __name__ == '__main__':
    test_item_path = test_list()
    test_get_attributes(test_item_path)
    #known_item_path = ''
    test_get_secret(known_item_path)
    test_create_credential()
    test_edit_credential()
