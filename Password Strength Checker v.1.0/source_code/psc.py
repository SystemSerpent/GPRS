import tkinter as tk
from tkinter import messagebox
import re

class PasswordCheckerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Checker")
        self.root.geometry("400x250")
        self.root.resizable(False, False)


        self.label = tk.Label(root, text="Enter your password:", font=("Arial", 14))
        self.label.pack(pady=10)


        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(root, textvariable=self.password_var, show="*", font=("Arial", 14), width=30)
        self.password_entry.pack(pady=5)
        self.password_entry.focus()



        self.check_button = tk.Button(root, text="Check Strength", command=self.check_strength, font=("Arial", 12))
        self.check_button.pack(pady=10)



        self.result_label = tk.Label(root, text="", font=("Arial", 12))
        self.result_label.pack(pady=10)



        self.clear_button = tk.Button(root, text="Clear", command=self.clear, font=("Arial", 12))
        self.clear_button.pack(pady=5)

    def check_strength(self):
        password = self.password_var.get()
        if not password:
            messagebox.showwarning("Input Error", "Please enter a password.")
            return

        strength, reasons = self.evaluate_password(password)
        if strength == 5:
            msg = "Strong password! ✅"
            color = "green"
        elif 3 <= strength < 5:
            msg = "Moderate password, but you can improve:\n" + "\n".join(reasons)
            color = "orange"
        else:
            msg = "Weak password, please improve:\n" + "\n".join(reasons)
            color = "red"

        self.result_label.config(text=msg, fg=color)

    def evaluate_password(self, password):
        strength = 0
        reasons = []

        if len(password) >= 8:
            strength += 1
        else:
            reasons.append("Password is too short (min 8 characters).")

        if re.search(r"[a-z]", password):
            strength += 1
        else:
            reasons.append("Add lowercase letters.")

        if re.search(r"[A-Z]", password):
            strength += 1
        else:
            reasons.append("Add uppercase letters.")

        if re.search(r"\d", password):
            strength += 1
        else:
            reasons.append("Add digits.")

        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            strength += 1
        else:
            reasons.append("Add special characters.")

        return strength, reasons

    def clear(self):
        self.password_var.set("")
        self.result_label.config(text="")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordCheckerApp(root)
    root.mainloop()
