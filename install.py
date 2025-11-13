from random import randint
import os
import platform

from flask import Flask, request, redirect, abort, Response, url_for, render_template

import tool
import data

print("Installing PIP Package")
os.system("pip install -r requirements.txt")
#install_pin = str(randint(0, 999999999)).zfill(9)
install_pin = "000000000"

app = Flask(__name__, template_folder="install_templates")
print(f"Install PIN : {install_pin}")
"""@app.before_request
def check_pin():
    if request.endpoint == "input_pin": return
    if request.cookies.get("pin", "") != install_pin:
        return render_template("password.html"), 403"""
@app.route("/input_pin", methods = ["POST"])
def input_pin():
    resp = redirect(url_for("welcome"))
    resp.set_cookie("pin", request.form["pin"], httponly=True)
    return resp
"""@app.route("/", methods = ["GET", "POST"])
def select_lang():
    return render_template("select_lang.html")"""
@app.route("/")
def welcome():
    platform.system()
    return render_template("welcome.html")

if __name__ == "__main__": app.run(port = 5000, debug = True)