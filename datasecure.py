import streamlit as st
import hashlib
import json
import time
from cryptography.fernet import Fernet 
import base64
import uuid

# Initialize session state variables if they don't exist
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
if 'current_page' not in st.session_state:
    st.session_state.current_page = "Home"
if 'last_attempt_time' not in st.session_state:
    st.session_state.last_attempt_time = 0

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to generate a key from passkey (for encryption)
def generate_key_from_passkey(passkey):
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashed[:32])

# Function to encrypt data
def encrypt_data(text, passkey):
    key = generate_key_from_passkey(passkey)
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey, data_id):
    try:
        hashed_passkey = hash_passkey(passkey)
        if data_id in st.session_state.stored_data and st.session_state.stored_data[data_id]["passkey"] == hashed_passkey:
            key = generate_key_from_passkey(passkey)
            cipher = Fernet(key)
            decrypted = cipher.decrypt(encrypted_text.encode()).decode()
            st.session_state.failed_attempts = 0
            return decrypted
        else:
            st.session_state.failed_attempts += 1
            st.session_state.last_attempt_time = time.time()
            return None
    except Exception:
        st.session_state.failed_attempts += 1
        st.session_state.last_attempt_time = time.time()
        return None

# Generate a unique data ID
def generate_data_id():
    return str(uuid.uuid4())

# Reset failed attempts
def reset_failed_attempts():
    st.session_state.failed_attempts = 0

# Change page
def change_page(page):
    st.session_state.current_page = page

# UI Title
st.title("🔒 Secure Data Encryption System")

# Sidebar Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu, index=menu.index(st.session_state.current_page))
st.session_state.current_page = choice

# Lockout on failed attempts
if st.session_state.failed_attempts >= 3:
    st.session_state.current_page = "Login"
    st.warning("🔒 Too many failed attempts! Reauthorization required.")

# Home Page
if st.session_state.current_page == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Store New Data", use_container_width=True):
            change_page("Store Data")
    with col2:
        if st.button("Retrieve Data", use_container_width=True):
            change_page("Retrieve Data")
    
    st.info(f"Currently storing {len(st.session_state.stored_data)} encrypted data entries.")

# Store Data Page
elif st.session_state.current_page == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")
    confirm_passkey = st.text_input("Confirm Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey and confirm_passkey:
            if passkey != confirm_passkey:
                st.error("⚠️ Passkeys do not match!")
            else:
                data_id = generate_data_id()
                hashed_passkey = hash_passkey(passkey)
                encrypted_text = encrypt_data(user_data, passkey)
                st.session_state.stored_data[data_id] = {
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_passkey
                }
                st.success("✅ Data stored securely!")
                st.code(data_id, language="text")
                st.info("⚠️ Save this Data ID! You'll need it to retrieve your data.")
        else:
            st.error("⚠️ All fields are required!")

# Retrieve Data Page
elif st.session_state.current_page == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    attempts_remaining = 3 - st.session_state.failed_attempts
    st.info(f"Attempts remaining: {attempts_remaining}")
    
    data_id = st.text_input("Enter Data ID:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if data_id and passkey:
            if data_id in st.session_state.stored_data:
                encrypted_text = st.session_state.stored_data[data_id]["encrypted_text"]
                decrypted_text = decrypt_data(encrypted_text, passkey, data_id)

                if decrypted_text:
                    st.success("✅ Decryption successful!")
                    st.markdown("### Your Decrypted Data:")
                    st.code(decrypted_text, language="text")
                else:
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - st.session_state.failed_attempts}")
            else:
                st.error("❌ Data ID not found!")
            
            if st.session_state.failed_attempts >= 3:
                st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                st.session_state.current_page = "Login"
                st.rerun()
        else:
            st.error("⚠️ Both fields are required!")

# Login / Reauthorization Page
elif st.session_state.current_page == "Login":
    st.subheader("🔑 Reauthorization Required")
    wait_time = 10
    time_since_last_attempt = time.time() - st.session_state.last_attempt_time

    if st.session_state.failed_attempts >= 3 and time_since_last_attempt < wait_time:
        remaining_time = int(wait_time - time_since_last_attempt)
        st.warning(f"🕒 Please wait {remaining_time} seconds before trying again.")
    else:
        login_pass = st.text_input("Enter Master Password:", type="password")
        if st.button("Login"):
            if login_pass == "admin123":  # Replace with secure method in production
                reset_failed_attempts()
                st.success("✅ Reauthorized successfully!")
                st.session_state.current_page = "Home"
                st.rerun()
            else:
                st.error("❌ Incorrect password!")

# Footer
st.markdown("---")
st.markdown("🔐 **Secure Data Encryption System** | Educational Project")

