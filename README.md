# Password Manager

## Description
A simple command-line password manager written in Java. It securely stores and retrieves passwords using AES encryption and PBKDF2 key derivation.

## Features
- Encrypts and stores passwords securely.
- Uses PBKDF2 for key derivation.
- AES encryption for password storage.
- Allows adding and retrieving passwords.
- Stores data in a local file (`passwords.txt`).

## Encryption Details
This password manager utilizes a combination of **PBKDF2** and **AES encryption** for secure password storage:

1. **Key Derivation using PBKDF2**:
   - The master password is used to generate a cryptographic key using PBKDF2 (`PBKDF2WithHmacSHA256`).
   - A **16-byte salt** is randomly generated and stored alongside the derived key.
   - The key derivation function runs for **1024 iterations**, making brute-force attacks difficult.

2. **AES Encryption for Password Storage**:
   - The generated key is used for **AES encryption (AES-128 in ECB mode)**.
   - When storing a password, it is first encrypted using AES and then encoded using Base64.
   - When retrieving a password, the encrypted text is decoded from Base64 and decrypted using AES with the derived key.

## Usage
1. **Compile the Program:**
   ```sh
   javac PasswordManager.java
   ```
2. **Run the Program:**
   ```sh
   java PasswordManager
   ```
3. **Follow the prompts:**
   - Enter a master password (first-time setup).
   - Choose an option:
     - `a` to add a password.
     - `r` to retrieve a password.
     - `q` to quit.

## File Format
```
salt:encrypted_master_key
label1:encrypted_password1
label2:encrypted_password2
```

## Example Run
```
Enter the passcode to access your passwords: supersecret
a : Add Password
r : Read Password
q : Quit
Enter choice: a
Enter label for password: GitHub
Enter password to store: mypassword123
Password successfully added.
Enter choice: r
Enter label for password: GitHub
Found: mypassword123
Enter choice: q
Quitting.
```




