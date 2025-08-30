import secretstorage
import time
import tempfile
import os
import logging
import threading

logger = logging.getLogger(__name__)
logger.debug("Loading Credential Service…")
class CredentialService:
    """
    A service class to handle all interactions with the
    Freedesktop.org Secret Service via the secretstorage library.
    """

    def __init__(self):
        """Initializes the D-Bus connection."""
        try:
            self.bus = secretstorage.dbus_init()
        except Exception as e:
            logger.exception("Failed to initialize D-Bus connection")
            # In a real application, you might want to handle this more gracefully.
            raise

    def list_credentials(self) -> list[dict]:
        """
        Lists all available credentials, returning their label and path.
        """
        logger.debug("Listing all available credentials…")
        all_items = []
        collections = secretstorage.get_all_collections(self.bus)
        for collection in collections:
            for item in collection.get_all_items():
                all_items.append(
                    {
                        "label": item.get_label(),
                        "attributes": item.get_attributes(),
                        "path": item.item_path,
                    }
                )
        return all_items

    def get_credential_attributes(self, item_path: str) -> dict | None:
        """
        Retrieves the public attributes for a specific credential.
        """
        logger.debug(f"Getting attributes for item: {item_path}")
        try:
            item = secretstorage.Item(self.bus, item_path)
            return item.get_attributes()
        except secretstorage.exceptions.ItemNotFoundException:
            return None

    def get_credential_secret(self, item_path: str) -> str | None:
        """
        Retrieves the secret for a specific credential, handling unlocking.
        """
        logger.debug(f"Getting secret for item: {item_path}")
        try:
            item = secretstorage.Item(self.bus, item_path)
            if item.is_locked():
                logger.debug("Item is locked, requesting unlock…")
                try:
                    _ = item.unlock()
                except Exception:
                    # Some backends may raise when prompt dismissed
                    logger.info("Unlock prompt dismissed by user.")
                    return None

                # Bounded poll for up to 5 seconds to avoid race conditions
                for _ in range(50):
                    if not item.is_locked():
                        break
                    time.sleep(0.1)

                if item.is_locked():
                    logger.warning("Unlock failed or was denied after waiting.")
                    return None

            logger.debug("Item unlocked, retrieving secret.")
            return item.get_secret().decode("utf-8")

        except secretstorage.exceptions.ItemNotFoundException:
            return None
        except secretstorage.exceptions.PromptDismissedException:
            logger.info("Prompt was dismissed by the user.")
            return None

    def _delete_file_after_delay(self, path: str, delay: int):
        """Delete a file after a specified delay using a background timer."""
        def _remove():
            try:
                os.remove(path)
                logger.debug(f"Successfully deleted temporary secret file: {path}")
            except OSError as e:
                logger.warning(f"Error deleting temporary secret file {path}: {e}")

        timer = threading.Timer(delay, _remove)
        timer.daemon = True
        timer.start()

    def get_credential_secret_as_temp_file(self, item_path: str, timeout: int = 60) -> str | None:
        """
        Retrieves a secret, writes it to a temporary file, and schedules
        the file for deletion after a timeout.
        Returns the absolute path to the temporary file.
        """
        secret = self.get_credential_secret(item_path)
        if secret is None:
            return None
        
        # Create a temporary file (mode 0o600 by default). Optionally prefer
        # tmpfs (/dev/shm) when PREFER_SHM=true and writable.
        prefer_shm = os.getenv("PREFER_SHM", "true").lower() == "true"
        mkstemp_dir = None
        if prefer_shm and os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK | os.X_OK):
            mkstemp_dir = "/dev/shm"
            logger.debug("Using /dev/shm for temporary secret file as requested.")
        try:
            fd, temp_file_path = tempfile.mkstemp(dir=mkstemp_dir)
        except Exception as e:
            logger.debug(f"mkstemp in {mkstemp_dir or 'default temp dir'} failed: {e}; falling back to system default")
            fd, temp_file_path = tempfile.mkstemp()
        logger.debug(f"Created temporary file for secret at: {temp_file_path}")
        
        try:
            # Write the secret to the temporary file
            with os.fdopen(fd, 'w') as temp_file:
                temp_file.write(secret)
            
            # Schedule the file for deletion via background timer
            self._delete_file_after_delay(temp_file_path, timeout)
            logger.debug(f"Scheduled {temp_file_path} for deletion in {timeout} seconds.")

            return temp_file_path
        except Exception as e:
            logger.exception("Failed to write secret to temporary file")
            # Clean up the file if writing fails
            os.remove(temp_file_path)
            return None

    def create_credential(self, label: str, password: str, attributes: dict) -> str:
        """
        Creates a new credential.
        """
        logger.info("Creating new credential with label: %r", label)
        collection = secretstorage.get_default_collection(self.bus)
        item = collection.create_item(label, attributes, password.encode('utf-8'), content_type="text/plain")
        return item.item_path

    def edit_credential(self, item_path: str, new_label: str = None, new_password: str = None, new_attributes: dict = None) -> bool:
        """
        Edits an existing credential.
        Allows updating the label, password, and attributes.
        """
        logger.info("Editing credential: %s", item_path)
        try:
            item = secretstorage.Item(self.bus, item_path)
            
            if new_label:
                item.set_label(new_label)
                logger.debug(f"  - Set label to: {new_label}")

            if new_password:
                item.set_secret(new_password.encode('utf-8'))
                logger.debug("  - Set new secret.")

            if new_attributes:
                item.set_attributes(new_attributes)
                logger.debug(f"  - Set attributes to: {new_attributes}")
            
            return True
        except secretstorage.exceptions.ItemNotFoundException:
            logger.warning(f"  - Error: Item not found at {item_path}")
            return False

    def search_credentials(self, attributes: dict) -> list[dict]:
        """Search for items matching attributes; returns list of dicts like list_credentials."""
        logger.debug(f"Searching credentials with attributes: {attributes}")
        items = secretstorage.search_items(self.bus, attributes)
        results = []
        for item in items:
            try:
                results.append(
                    {
                        "label": item.get_label(),
                        "attributes": item.get_attributes(),
                        "path": item.item_path,
                    }
                )
            except Exception:
                continue
        return results

    def delete_credential(self, item_path: str) -> bool:
        """Delete a credential item by path."""
        logger.info("Deleting credential at: %s", item_path)
        try:
            item = secretstorage.Item(self.bus, item_path)
            item.delete()
            return True
        except secretstorage.exceptions.ItemNotFoundException:
            logger.warning(f"Item not found for deletion: {item_path}")
            return False
