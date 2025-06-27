import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from cryptography.fernet import Fernet
import os
import json
import base64
import hashlib
import secrets
import string
import re

DATA_FILE = "vault.dat"
SALT_FILE = "salt.bin"

def generate_key(master_password, salt):
    return base64.urlsafe_b64encode(hashlib.pbkdf2_hmac(
        'sha256', master_password.encode(), salt, 100000))

def suggest_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))

def evaluate_strength(password):
    score = 0
    if len(password) >= 8: score += 1
    if re.search(r"[a-z]", password): score += 1
    if re.search(r"[A-Z]", password): score += 1
    if re.search(r"\d", password): score += 1
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): score += 1
    return score

def encrypt_data(data, fernet):
    return fernet.encrypt(json.dumps(data).encode())

def decrypt_data(data, fernet):
    return json.loads(fernet.decrypt(data).decode())

def save_data(data, fernet):
    with open(DATA_FILE, 'wb') as f:
        f.write(encrypt_data(data, fernet))

def load_data(fernet):
    if not os.path.exists(DATA_FILE):
        return []
    with open(DATA_FILE, 'rb') as f:
        return decrypt_data(f.read(), fernet)

class PasswordManagerApp:
    def __init__(self, root, fernet, data):
        self.fernet = fernet
        self.data = data
        self.root = root
        self.root.title("Secure Password Manager")

        self.tree = ttk.Treeview(root, columns=("Username", "Password", "Note"), show="headings")
        self.tree.heading("Username", text="Username/Email")
        self.tree.heading("Password", text="Password")
        self.tree.heading("Note", text="Note")
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=5)

        tk.Button(btn_frame, text="Add Entry", command=self.add_entry).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Suggest Password", command=self.suggest_password).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Save", command=self.save).pack(side=tk.LEFT, padx=5)

        self.load_entries()

    def load_entries(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        for item in self.data:
            self.tree.insert('', tk.END, values=(item['username'], item['password'], item.get('note', '')))

    def add_entry(self):
        top = tk.Toplevel(self.root)
        top.title("Add New Entry")

        tk.Label(top, text="Username/Email:").pack()
        username_entry = tk.Entry(top)
        username_entry.pack()

        tk.Label(top, text="Password:").pack()
        password_entry = tk.Entry(top)
        password_entry.pack()

        tk.Label(top, text="Note (optional):").pack()
        note_entry = tk.Entry(top)
        note_entry.pack()

        strength_var = tk.IntVar()
        strength_bar = ttk.Progressbar(top, length=200, mode='determinate', variable=strength_var, maximum=5)
        strength_bar.pack(pady=5)

        def on_password_change(*args):
            password = password_entry.get()
            strength_var.set(evaluate_strength(password))

        password_entry.bind("<KeyRelease>", on_password_change)

        def submit():
            entry = {
                "username": username_entry.get(),
                "password": password_entry.get(),
                "note": note_entry.get()
            }
            self.data.append(entry)
            self.load_entries()
            top.destroy()

        tk.Button(top, text="Add", command=submit).pack(pady=5)

    def suggest_password(self):
        pwd = suggest_password()
        messagebox.showinfo("Suggested Password", pwd)

    def save(self):
        save_data(self.data, self.fernet)
        messagebox.showinfo("Saved", "Data encrypted and saved successfully.")

def start_app():
    master_password = simpledialog.askstring("Master Password", "Enter your master password:", show='*')
    if not master_password:
        return

    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, 'rb') as f:
            salt = f.read()
    else:
        salt = os.urandom(16)
        with open(SALT_FILE, 'wb') as f:
            f.write(salt)

    key = generate_key(master_password, salt)
    fernet = Fernet(key)

    try:
        data = load_data(fernet)
    except Exception:
        messagebox.showerror("Error", "Wrong master password or corrupted file.")
        return

    root = tk.Tk()
    app = PasswordManagerApp(root, fernet, data)
    root.mainloop()

start_app()
