from cryptography.fernet import Fernet
import pyotp
import os

class PasswordManager:

    def __init__(self):
        """
        Initializes the PasswordManager.
        
        - `self.key`: The encryption key for Fernet.
        - `self.password_file`: Path to the encrypted password file.
        - `self.password_dict`: Dictionary to store decrypted passwords.
        - `self.totp_secret`: The secret key for TOTP MFA.
        - `self.is_authenticated`: A flag to check if the user has passed MFA.
        """
        self.key = None
        self.password_file = None
        self.password_dict = {}
        self.totp_secret = None
        self.is_authenticated = False

    def create_key(self, path):
        """
        Generates a new Fernet key and saves it to a file.
        
        Args:
            path (str): The file path to save the key.
        """
        self.key = Fernet.generate_key()
        with open(path, 'wb') as f:
            f.write(self.key)
        print(f"Encryption key created and saved to '{path}'.")

    def load_key(self, path):
        """
        Loads an existing Fernet key from a file.
        
        Args:
            path (str): The file path to load the key from.
        """
        try:
            with open(path, 'rb') as f:
                self.key = f.read()
            print(f"Encryption key loaded from '{path}'.")
            return True
        except FileNotFoundError:
            print(f"Error: Key file '{path}' not found.")
            return False

    def create_password_file(self, path, initial_values=None):
        """
        Creates a new empty password file.
        
        Args:
            path (str): The file path for the new password file.
            initial_values (dict, optional): A dictionary of initial passwords to add.
        """
        self.password_file = path
        # Create an empty file to ensure it exists.
        open(path, 'a').close()
        
        if initial_values is not None:
            for site, password in initial_values.items():
                self.add_password(site, password)
        print(f"Password file created at '{path}'.")

    def load_password_file(self, path): 
        """
        Loads and decrypts passwords from an existing file.
        It also loads the TOTP secret if it exists.
        
        Args:
            path (str): The file path of the password file.
        """
        self.password_file = path
        self.password_dict = {}
        self.totp_secret = None
        
        try:
            with open(path, 'r') as f:
                for line in f:
                    # Split the line only on the first colon to handle passwords with colons.
                    site, encrypted = line.strip().split(":", 1)
                    try:
                        decrypted_password = Fernet(self.key).decrypt(encrypted.encode()).decode()
                        self.password_dict[site] = decrypted_password
                        # Check for the special MFA secret key
                        if site == "_MFA_SECRET_":
                            self.totp_secret = decrypted_password
                            # Do not store the secret in the password_dict for security
                            del self.password_dict[site]
                    except Exception as e:
                        print(f"Error decrypting line for site '{site}': {e}")
            print(f"Password file loaded from '{path}'.")
            return True
        except FileNotFoundError:
            print(f"Error: Password file '{path}' not found.")
            return False
        except Exception as e:
            print(f"Error loading password file: {e}")
            return False

    def add_password(self, site, password):
        """
        Adds a new password to the dictionary and saves it to the file.
        
        Args:
            site (str): The site name.
            password (str): The password.
        """
        if not self.is_authenticated:
            print("Authentication required. Please verify your MFA token first.")
            return
            
        self.password_dict[site] = password
        
        if self.password_file is not None:
            with open(self.password_file, 'a+') as f:
                encrypted = Fernet(self.key).encrypt(password.encode())
                f.write(site + ":" + encrypted.decode() + "\n")
            print(f"Password for '{site}' added.")
        else:
            print("No password file loaded. Password added to memory only.")

    def get_password(self, site):
        """
        Retrieves a decrypted password for a given site.
        
        Args:
            site (str): The site name.
            
        Returns:
            str: The password or an error message if not found.
        """
        if not self.is_authenticated:
            print("Authentication required. Please verify your MFA token first.")
            return None
            
        return self.password_dict.get(site, "Password not found.")

    def setup_mfa(self):
        """
        Generates and saves a TOTP secret.
        This secret must be added to a mobile authenticator app.
        """
        if self.totp_secret:
            print("MFA is already set up.")
            return
        
        if not self.key or not self.password_file:
            print("You must load a key and a password file before setting up MFA.")
            return

        # Generate a new base32 secret
        self.totp_secret = pyotp.random_base32()
        
        # Save the secret to the encrypted file under a special key
        encrypted_secret = Fernet(self.key).encrypt(self.totp_secret.encode())
        with open(self.password_file, 'a+') as f:
            f.write("_MFA_SECRET_:" + encrypted_secret.decode() + "\n")
            
        print("\nMFA Secret generated. Please add this secret to your authenticator app:")
        print(f"\nSecret: {self.totp_secret}\n")
        
        # This URL can be used to scan a QR code with your authenticator app
        # Replace 'PasswordManagerApp' and 'user@example.com' with your own details
        otp_uri = pyotp.totp.TOTP(self.totp_secret).provisioning_uri(
            name='user@example.com',
            issuer_name='PythonPasswordManager'
        )
        print(f"Or, you can use this URI to generate a QR code for your authenticator app: {otp_uri}\n")
        print("MFA setup is complete. The secret has been saved in your password file.")

    def verify_mfa(self, token):
        """
        Verifies the provided TOTP token against the stored secret.
        
        Args:
            token (str): The token entered by the user.
            
        Returns:
            bool: True if the token is valid, False otherwise.
        """
        if not self.totp_secret:
            print("MFA is not configured for this password file.")
            self.is_authenticated = True
            return True # Allow access if no MFA is set up
        
        totp = pyotp.TOTP(self.totp_secret)
        if totp.verify(token):
            self.is_authenticated = True
            print("MFA token is valid. Access granted.")
            return True
        else:
            print("Invalid MFA token. Access denied.")
            return False


def main():
    pm = PasswordManager()

    while True:
        print("\n--- Password Manager Menu ---")
        print("(1) Create a new key")
        print("(2) Load an existing key")      
        print("(3) Create a new password file")
        print("(4) Load an existing password file")
        print("(5) Setup MFA (First-time only)")
        if pm.is_authenticated:
            print("(6) Add a new password")
            print("(7) Get a password")
        print("(q) Quit")

        choice = input("Enter your choice: ")
        
        if choice == "1":
            path = input("Enter path to save the new key: ")
            pm.create_key(path)
        
        elif choice == "2":
            path = input("Enter path to load the key: ")
            if pm.load_key(path):
                # If key is loaded, but no password file is loaded yet, allow access.
                # MFA check will happen when the password file is loaded.
                pass
        
        elif choice == "3":
            path = input("Enter path for the new password file: ")
            pm.create_password_file(path)
        
        elif choice == "4":
            if not pm.key:
                print("Please load a key first (option 2).")
                continue
            
            path = input("Enter path to load the password file: ")
            if pm.load_password_file(path):
                if pm.totp_secret:
                    # If MFA is configured, prompt for the token
                    mfa_token = input("Enter your MFA token from your authenticator app: ")
                    pm.verify_mfa(mfa_token)
                else:
                    # If no MFA is configured, authenticate directly
                    pm.is_authenticated = True
                    print("No MFA configured. Access granted.")

        elif choice == "5":
            pm.setup_mfa()

        elif choice == "6" and pm.is_authenticated:
            site = input("Enter the site: ")
            password = input("Enter the password: ")
            pm.add_password(site, password)
        
        elif choice == "7" and pm.is_authenticated:
            site = input("What site do you want: ")
            password = pm.get_password(site)
            if password is not None:
                print(f"Password for {site}: {password}")

        elif choice == "q": 
            print("Goodbye!")
            break

        else:
            print("Invalid choice or action not allowed without authentication.")

if __name__ == "__main__":
    main()
