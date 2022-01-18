#!/usr/bin/python3

from flask import Flask, request, render_template, redirect, url_for
from Utils.utils import *
from bot import admin_check
import os, json
from config import FLAG
from requests.utils import unquote

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

KEY = os.urandom(16)


@app.route("/", methods=["GET"])
def root():
    if request.method == "GET":
        return redirect(url_for("generate_token"))


@app.route("/generate_token", methods=["GET", "POST"])
def generate_token():
    if request.method == "GET":
        return render_template("./generate_token.html")
    elif request.method == "POST":
        correct = True
        name = request.form.get("name")
        token = {"type": "VIP"}
        IV = os.urandom(16)

        try:
            token["name"] = name
            dumped_token = json.dumps(token).encode()

            enc = encrypt(dumped_token, KEY, IV)

            result = f"Your token : {enc}"
            correct = True
        except:
            result = "something is going wrong"

        return render_template("./generate_token.html", result=result, correct=correct)


@app.route("/check_ticket", methods=["GET", "POST"])
def check_ticket():
    ticket = None

    if request.method == "GET":
        return render_template("./check_ticket.html", ticket=ticket)
    elif request.method == "POST":
        token = request.form.get("token")

        try:
            data = decrypt(token, KEY)
            ticket = Ticket(data)

            # launch the bot to valid the ticket
            ticket_object = vars(ticket)
            admin_check(ticket_object)

            result = "The admin verified you ticket"
            return render_template(
                "./check_ticket.html", result=result, ticket=ticket_object
            )

        except Exception as e:
            print(e)
            result = "something is going wrong"
            ticket = None
            return render_template("./check_ticket.html", result=result, ticket=ticket)


@app.route("/validate_ticket", methods=["GET"])
def validate_ticket():
    if request.method == "GET":
        # verify that the cookie is for the admin
        if request.cookies.get("flag") and request.cookies["flag"] == FLAG:
            ticket = {
                "url": unquote(request.args.get("ticket_url")),
                "type": unquote(request.args.get("ticket_type")),
            }

            return render_template("./validate_ticket.html", ticket=ticket)
        else:
            return "You're not an administrator, you can't access this page."
