# streamlit_app.py
import streamlit as st
from hill_cipher import encrypt, decrypt, matrix_mod_inv

#  Page setup
st.set_page_config(page_title="Hill Cipher App", layout="centered")
st.title("🔐 Hill Cipher Encryption & Decryption")
st.markdown("### Welcome to my Hill Cipher App ")

# ---------------------------- Inputs ----------------------------

st.subheader("🧮 Enter Key Matrix")
st.markdown("Enter rows separated by ';' and numbers by commas. Example:")
st.code("3,3;2,5  → means [[3,3],[2,5]]")

key_str = st.text_input("Key Matrix", value="3,3;2,5")

plaintext = st.text_area("📝 Enter Text", value="HELLO")
pad_char = st.text_input("Pad Character (for last block fill)", value="X", max_chars=1)

option = st.radio("Select Operation:", ["Encrypt", "Decrypt"])


# ---------------------------- Logic ----------------------------

def parse_key(key_str):
    """Convert user input string -> 2D list matrix"""
    rows = [row.strip() for row in key_str.split(";") if row.strip()]
    matrix = []
    for r in rows:
        nums = [int(x.strip()) for x in r.split(",") if x.strip()]
        matrix.append(nums)
    n = len(matrix)
    if any(len(row) != n for row in matrix):
        raise ValueError("Matrix must be square (n x n).")
    return matrix


# ---------------------------- Action ----------------------------
if st.button("Run Cipher"):
    try:
        key_matrix = parse_key(key_str)
        st.write("✅ Key Matrix Detected:", key_matrix)

        # check invertibility
        try:
            _ = matrix_mod_inv(key_matrix, 26)
            st.success("Key is invertible mod 26 ✅")
        except Exception as e:
            st.error(f"Key is NOT invertible mod 26: {e}")

        if option == "Encrypt":
            result = encrypt(plaintext, key_matrix, pad_char=pad_char)
            st.success("🔒 Encrypted Text:")
            st.code(result, language='text')
        else:
            result = decrypt(plaintext, key_matrix)
            st.success("🔓 Decrypted Text:")
            st.code(result, language='text')

    except Exception as e:
        st.error(f"Error: {e}")
