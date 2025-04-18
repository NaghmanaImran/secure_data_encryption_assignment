import streamlit as st
import sqlite3
import os
from cryptography.fernet import Fernet
import hashlib

KEY_FILE = "simple_secret.key"

# Function to generate/load encryption key
def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return key

# Load encryption key and create Fernet instance
key = load_key()
cipher = Fernet(key)

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect("simple_data.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS vault(
                  label TEXT PRIMARY KEY,
                  encrypted_text TEXT,
                  passkey TEXT)""")
    conn.commit()
    conn.close()

# Helper functions
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# Main App
def main():
    st.title(" Secure Data Encryption App")
    init_db()

    menu = ["Store Secret", "Retrieve Secret"]
    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Store Secret":
        st.header(" Store a New Secret")

        label = st.text_input("Label (unique):")
        secret = st.text_area("Your Secret")
        passkey = st.text_input("Passkey (to protect it):", type="password")

        if st.button("Encrypt and Save"):
            if label and secret and passkey:
                conn = sqlite3.connect("simple_data.db")
                c = conn.cursor()

                encrypted = encrypt(secret)
                hashed_key = hash_passkey(passkey)

                try:
                    c.execute("INSERT INTO vault(label, encrypted_text, passkey) VALUES (?, ?, ?)",
                              (label, encrypted, hashed_key))
                    conn.commit()
                    st.success("Secret saved successfully!")
                except sqlite3.IntegrityError:
                    st.error("Label already exists!")
                conn.close()
            else:
                st.warning(" Please fill all fields.")

    elif choice == "Retrieve Secret":
        st.header(" Retrieve Your Secret")

        label = st.text_input("Enter Label:")
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Decrypt"):
            conn = sqlite3.connect("simple_data.db")
            c = conn.cursor()
            c.execute("SELECT encrypted_text, passkey FROM vault WHERE label = ?", (label,))
            result = c.fetchone()
            conn.close()

            if result:
                encrypted_text, stored_hash = result

                if hash_passkey(passkey) == stored_hash:
                    try:
                        decrypted_text = decrypt(encrypted_text)
                        st.success(" Here is your secret:")
                        st.code(decrypted_text)
                    except Exception as e:
                        st.error(" Error decrypting the secret.")
                else:
                    st.error(" Incorrect passkey.")
            else:
                st.warning(" No such label found.")

if __name__ == "__main__":
    main()
