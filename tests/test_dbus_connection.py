import secretstorage
import time

def main():
    """
    Performs a verbose, delayed check on the unlock status.
    """
    print("--- Verbose D-Bus Unlock Debug ---")
    try:
        # 1. Verbose D-Bus connection
        print("Initializing D-Bus connection...")
        bus = secretstorage.dbus_init()
        print(f"D-Bus connection object: {bus!r}")

        # 2. Find the item
        search_attributes = {"url": "http://samplewebsite.com"}
        print(f"Searching for items with attributes: {search_attributes}")
        items = list(secretstorage.search_items(bus, search_attributes))

        if not items:
            print("No matching item found.")
            return

        # 3. Verbose item details
        item = items[0]
        print("\n--- Item Details ---")
        print(f"  Item object: {item!r}")
        print(f"  Label: {item.get_label()}")
        print(f"  Locked: {item.is_locked()}")
        print(f"  Attributes: {item.get_attributes()}")
        print(f"  Created: {item.get_created()}")
        print(f"  Modified: {item.get_modified()}")
        print("--------------------")

        if not item.is_locked():
            print("Item is already unlocked. Nothing to test.")
            return

        # 4. Attempt to unlock and then wait
        print("\nCalling item.unlock(). Please approve the prompt in KeePassXC.")
        unlock_result = item.unlock() # This should block
        print(f"Initial return value of item.unlock() was: {unlock_result!r}")
        
        print("\nWaiting for 5 seconds to allow for any signal delays...")
        time.sleep(5)

        # 5. Check the lock state again
        print("\n--- Post-Unlock Status Check ---")
        final_lock_state = item.is_locked()
        print(f"Is the item still locked now? {final_lock_state}")

        if not final_lock_state:
            print("Success! The item is now unlocked.")
            secret = item.get_secret().decode()
            # Do not print full secrets in logs; show length + prefix
            print(f"Secret retrieved (len={len(secret)}): {secret[:4]}…")
        else:
            print("Failure. The item remains locked even after a delay.")
            print("This strongly suggests an issue outside of this script's control.")

    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
