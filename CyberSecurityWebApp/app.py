from flask import Flask, render_template, request

app = Flask(__name__)

# Functions
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

@app.route("/", methods=["GET", "POST"])
def home():
    result = ""
    if request.method == "POST":
        if "password" in request.form:
            password = request.form["password"]
            result = check_weak_password(password)

        elif "url" in request.form:
            url = request.form["url"]
            result = detect_phishing(url)

        elif "filename" in request.form:
            file = request.form["filename"]
            result = detect_malware(file)

    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)