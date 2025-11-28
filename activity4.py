import tkinter as tk 
from tkinter import messagebox, simpledialog

# --- Functions ---

def check_weak_password(password):
    if len(password) < 6:
        return "⚠ Weak: Password too short!"
    elif password.isalpha() or password.isdigit():
        return "⚠ Weak: Use both letters and numbers!"
    elif "123" in password or "password" in password.lower():
        return "⚠ Weak: Too common!"
    else:
        return "✅ Strong password."

def detect_phishing(url):
    suspicious_keywords = ["login", "verify", "update", "free", "click"]
    if any(word in url.lower() for word in suspicious_keywords):
        return "⚠ Possible phishing link detected!"
    elif "https://" not in url:
        return "⚠ Not secure: Missing HTTPS!"
    else:
        return "✅ Safe link."
def detect_malware(filename):
    dangerous_extensions = [".exe", ".bat", ".vbs", ".scr"]
    if any(filename.endswith(ext) for ext in dangerous_extensions):
        return "⚠ Warning: File may contain malware!"
    else:
        return "✅ File looks safe."

# --- GUI Functions ---

def check_password_gui():
    pwd = simpledialog.askstring("Password Check", "Enter password to check:")
    if pwd:
        result = check_weak_password(pwd)
        messagebox.showinfo("Result", result)
def detect_phishing_gui():
    url = simpledialog.askstring("Phishing Link Check", "Enter website URL:")
    if url:
        result = detect_phishing(url)
        messagebox.showinfo("Result", result)
def detect_malware_gui():
    file = simpledialog.askstring("Malware Check", "Enter file name (with extension):")
    if file:
        result = detect_malware(file)
        messagebox.showinfo("Result", result)
def exit_app():
    window.destroy()

# --- Main Window ---

window = tk.Tk()
window.title("Cyber Security Threat Detector 🛡")
window.geometry("400x350")
window.config(bg="#1e1e2f")

title = tk.Label(window, text="Cyber Security Threat Detector", font=("Arial", 16, "bold"), fg="white", bg="#1e1e2f")
title.pack(pady=20)
btn1 = tk.Button(window, text="🔐 Check Weak Password", command=check_password_gui, width=25, height=2, bg="#2ecc71", fg="white", font=("Arial", 10, "bold"))
btn1.pack(pady=10)
btn2 = tk.Button(window, text="🔗 Detect Phishing Link", command=detect_phishing_gui, width=25, height=2, bg="#f1c40f", fg="black", font=("Arial", 10, "bold"))
btn2.pack(pady=10)

btn3 = tk.Button(window, text=" Detect Malware File", command=detect_malware_gui, width=25, height=2, bg="#e74c3c", fg="white", font=("Arial", 10, "bold"))
btn3.pack(pady=10)

exit_btn = tk.Button(window, text="❌ Exit", command=exit_app, width=10, bg="#34495e", fg="white", font=("Arial", 10, "bold"))
exit_btn.pack(pady=20)

window.mainloop()
