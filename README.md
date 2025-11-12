<h1 align="center">🔐 Hill Cipher Encryption System</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/Streamlit-App-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white"/>
  <img src="https://img.shields.io/badge/Numpy-Library-013243?style=for-the-badge&logo=numpy&logoColor=white"/>
</p>

---

## 🌟 Overview  
The **Hill Cipher Encryption System** is a **Python + Streamlit** project that encrypts and decrypts text using classical **matrix-based cryptography**.  
It visually demonstrates how mathematics and programming combine to secure information.

---

## ✨ Features
✅ Encrypt & decrypt text in real-time  
✅ Interactive **Streamlit** web interface  
✅ Beautiful UI with instant feedback  
✅ Clean modular Python code  
✅ Educational implementation of **matrix ciphering** logic  

---

## 🏗️ Project Structure
<img width="991" height="353" alt="image" src="https://github.com/user-attachments/assets/ae0ea806-7f74-45b4-8703-9952b6c9c49b" />


---

## 🖥️ Tech Stack
| Category | Tools Used |
|-----------|-------------|
| 💻 Programming | Python 3.11 |
| 🧠 Libraries | NumPy, Streamlit |
| 🧩 Concept | Cryptography, Matrix Algebra |
| 🎨 UI | Streamlit Components |

---

## ⚙️ Setup Instructions

### 🧩 Step 1: Clone the Repository

git clone https://github.com/Ishika-guptaa25/Hill-Cipher-Encryption.git
cd Hill-Cipher-Encryption

### 🧩 Step 2: Install Dependencies

pip install -r requirements.txt

### 🧩 Step 3: Run the Application

streamlit run streamlit_app.py
The app will open in your browser automatically 

---

## 🧮 Algorithm Logic (Simplified)
Hill Cipher is based on matrix multiplication modulo 26.

### Encryption

C = (K × P) mod 26
Decryption

P = (K⁻¹ × C) mod 26
K: key matrix
P: plaintext matrix
C: ciphertext matrix

If the key matrix is invertible mod 26 → encryption & decryption both work successfully!

---

## 🪄 Sample Run
Input (Plain Text): HELLO
Key Matrix: [[3, 3], [2, 5]]
Encrypted Text: HIOZHN
Decrypted Text: HELLOX

---

## 🖼️ App Preview
<img width="750" height="500" alt="image" src="https://github.com/user-attachments/assets/75a2112b-20b7-4e4f-b431-0c48f97013c3" />

### Encrypt Mode	
<img width="500" height="350" alt="image" src="https://github.com/user-attachments/assets/eddaeb6b-b144-4d85-aea7-bf6b187a2c59" />

### Decrypt Mode
<img width="500" height="350" alt="image" src="https://github.com/user-attachments/assets/9ecca7b2-90b8-4b93-b478-b8458b0fc2fe" />


---

## 🌐 Try It Online 
🚀 Launch the app instantly on Streamlit: https://hill-cipher-encryption-fynvigr5dd4mxxyub54bta.streamlit.app/

---

## 🧠 Future Enhancements
✨ Add support for different block sizes
✨ Implement Caesar and Vigenère Cipher options
✨ Enhance UI using Streamlit themes
✨ Add history of previous encryptions

---

## 📊 GitHub Stats
<p align="center"> <img src="https://github-readme-stats.vercel.app/api/pin/?username=Ishika-guptaa25&repo=Hill-Cipher-Encryption&theme=rose_pine&hide_border=true"/> </p>

---

## 👩‍💻 Author
Ishika Gupta
🎓 BCA Student | Python Developer 
📍 India

<p align="center"> <a href="https://github.com/Ishika-guptaa25"><img src="https://img.shields.io/badge/GitHub-Ishika--guptaa25-181717?style=for-the-badge&logo=github"/></a> <a href="https://www.linkedin.com/in/ishika-gupta-y25081402"><img src="https://img.shields.io/badge/LinkedIn-Ishika%20Gupta-FF69B4?style=for-the-badge&logo=linkedin&logoColor=white"/></a> </p>

---

## ⭐ Show Your Support
If you liked this project, give it a ⭐ on GitHub — it motivates me to build more awesome apps 💕

<p align="center"> <img src="https://img.shields.io/github/stars/Ishika-guptaa25/Hill-Cipher-Encryption?style=social"/> </p>
