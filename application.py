import os
import sqlite3
import re

#from cs50 import SQL

from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = sqlite3.connect('finance.db', check_same_thread=False)
db.row_factory = sqlite3.Row
crud = db.cursor()

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # fetch trade history from database for current user
    uid = (session["user_id"],)
    crud.execute('SELECT symbol, company, SUM(shares) as shares FROM transactions WHERE user_id=? GROUP BY symbol HAVING SUM(shares) != 0', uid)
    portfolio = crud.fetchall()

    # wrangle data to be sent to user
    input = []
    total = 0
    for row in portfolio:
        price = lookup(row["symbol"])["price"]
        input.append([row["symbol"], row["company"], row["shares"], usd(price), usd(row["shares"] * price)])
        total += row["shares"] * price

    crud.execute('SELECT cash FROM users WHERE id=?', uid)
    cash = crud.fetchone()["cash"]

    total = usd(total + cash)
    cash = usd(cash)

    flash("Last Update  :  {}".format(datetime.now().strftime("%B %d, %Y %H:%M:%S")))
    return render_template("index.html", input=input, cash=cash, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("Missing Symbol!")

        # Ensure a valid symbol was submitted
        if not lookup(request.form.get("symbol")):
            return apology("Invalid Symbol!")

        # Ensure number of shares was submitted
        if not request.form.get("shares"):
            return apology("Missing shares!")

        # Ensure posutive number of share was submitted
        if int(request.form.get("shares")) <= 0:
            return apology("Just Positive Number of Shares!")

        """ Purchase shares """
        symbol = request.form.get("symbol").upper()
        shares = int(request.form.get("shares"))

        stock = lookup(symbol)

        uid = (session["user_id"],)
        crud.execute('SELECT cash FROM users WHERE id=?', uid )
        cash = dict(crud.fetchall()[0])["cash"]

        # ensure user has enough cash to proceed with purchase
        if cash < shares * stock["price"]:
            return apology("Low Cash Balance!")
        else:
            # write the purchase transaction to the database
            transact = (session["user_id"], symbol, stock["name"], shares, stock["price"],)
            crud.execute('INSERT INTO transactions (user_id, symbol, company, shares, price) VALUES (?, ?, ?, ?, ?)', transact)
            db.commit()

            # update user's cash available
            balance = (cash - shares * stock["price"], uid[0])
            crud.execute('UPDATE users SET cash=? WHERE id=?', balance)
            db.commit()

            flash("Bought!")
            return redirect("/")


    else:
        # direct user to "buy" page
        return render_template("buy.html")


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""
    # grab data submitted via "GET"
    uname = (request.args.get("username"),)

    # Ensure username of at least lenth one submitted
    if not uname[0]:
        return jsonify(response = False)

    # Grab data from database
    crud.execute('SELECT username FROM users WHERE username=?', uname)
    uname_db = crud.fetchone()

    # send feedback to user if username is available or already taken
    if not uname_db:
        return jsonify(response = True)

    return jsonify(response = False)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # fetch data from database
    uid = (session["user_id"],)
    crud.execute('SELECT symbol, shares, price, dated FROM transactions WHERE user_id=? ORDER BY dated DESC', uid)
    rows = crud.fetchall()

    # wrangle data for sending to user
    input = []
    for row in rows:
        input.append([row["symbol"], row["shares"], usd(row["price"]), row["dated"]])

    return render_template("history.html", input=input)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        username = (request.form.get("username"),)
        crud.execute('SELECT * FROM users WHERE username=?', username)
        user = crud.fetchone()

        # Ensure username exists and password is correct
        if not user or not check_password_hash(user["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = user["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # handle user request for a quote on stocks
    if request.method == "POST":

        # Ensure symbol is submitted
        if not request.form.get("symbol"):
            return apology("Missing Symbol!", 403)

        # Let user know if symbol is not valid
        if not lookup(request.form.get("symbol")):
            return apology("Invalid Symbol!", 400)

        else:
            # send the stock price to user interface
            quote = lookup(request.form.get("symbol"))
            quote["price"] = usd(quote["price"])
            return render_template("quoted.html", quote = quote)

    # send user to page for getting a quote
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # user submitting thier registration info
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("Username must be provided!", 403)

        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("Password must be provided!", 403)

        # Ensure password was confirmed
        if not request.form.get("confirmation"):
            return apology("Re-enter password for confirmation", 403)

        # Ensure passwords match
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("Re-entered password does not match!", 403)

        # Ensure user is not registered already
        username = (request.form.get("username"),)
        crud.execute('SELECT * FROM users WHERE username=?', username)
        if crud.fetchone():
            return apology("Username taken!")

        # Ensure correct password pattern (strong!)
        pswd = request.form.get("password")
        if not re.search("[A-z]", pswd) or not re.search("[0-9]", pswd) or len(pswd) < 8:
            return apology("Follow pattern for strong password!")

        # register user
        registrant = (request.form.get("username"), generate_password_hash(request.form.get("password")))
        crud.execute('INSERT INTO users (username, hash) VALUES (?, ?)', registrant)
        db.commit()

        # keep registered user logged in
        crud.execute('SELECT id FROM users WHERE username=?', username)
        session["user_id"] = crud.fetchone()["id"]

        # write default deposit into database (deafault 10,000USD)
        crud.execute('SELECT cash FROM users WHERE username=?', username)
        deposit = (session["user_id"], crud.fetchone()["cash"],)
        crud.execute('INSERT INTO deposit (user_id, amount) VALUES (?, ?)', deposit)
        db.commit()

        flash("Successfully Registered!")
        return redirect("/")

    # direct user to registration page if not already
    else:
        return render_template("register.html")




@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("Missing Symbol!")

        # Ensure number of shares was submitted
        if not request.form.get("shares"):
            return apology("Missing shares!")

        # Ensure posutive number of share was submitted
        if int(request.form.get("shares")) <= 0:
            return apology("Just Positive Number of Shares!")

        # grab submitted shares data from database
        grab = (session["user_id"], request.form.get("symbol"),)
        crud.execute('SELECT SUM(shares) AS shares FROM transactions WHERE user_id=? AND symbol=? GROUP BY symbol', grab)
        shares = crud.fetchone()["shares"]

        # Ensure number of selling shares are not greater than what user posses
        if int(request.form.get("shares")) > shares:
            return apology("Try smaller shares!")

        # sell the shares and record the transaction in database
        stock = lookup(request.form.get("symbol"))

        transact = (session["user_id"], stock["symbol"], stock["name"], -int(request.form.get("shares")), stock["price"])
        crud.execute('INSERT INTO transactions (user_id, symbol, company, shares, price) VALUES (?, ?, ?, ?, ?)', transact)
        db.commit()

        # update user cash ballance
        # retrive current cash ballance from database
        uid = (session["user_id"],)
        crud.execute('SELECT cash FROM users WHERE id=?', uid)
        cash = crud.fetchone()["cash"]

        # update cash amount
        cash += int(request.form.get("shares")) * stock["price"]

        # write changes to database
        balance = (cash, session["user_id"],)
        crud.execute('UPDATE users SET cash=? WHERE id=?', balance)
        db.commit()


        # send feedback to user
        flash("Sold!")
        return redirect("/")


    else:

        # fetch name of all stocks that user posses from database
        uid = (session["user_id"],)
        crud.execute("SELECT DISTINCT symbol FROM transactions WHERE user_id=?", uid)
        rows = crud.fetchall()

        # make list out of symbols
        input=[]
        for row in rows:
            input.append(row["symbol"])

        # render the data for user selection
        return render_template("sell.html", input=input)


@app.route("/chpass", methods=["GET", "POST"])
def change_password():
    """ Change Password """

    # Change the password if user asked
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("Missing Username!")

        # Ensure current password was submitted
        if not request.form.get("oldpass"):
            return apology("Missing Current Pass!")

        # Ensure new password was submitted
        if not request.form.get("newpass"):
            return apology("Missing New Pass!")

        # Ensure new pass was confirmed
        if not request.form.get("confirmpass"):
            return apology("Confirm Your New Pass")

        # Ensure new password and its confirmation match
        if request.form.get("newpass") != request.form.get("confirmpass"):
            return apology("Passwords do not match!")

        # grab username and check if current data is registered on database
        uname = (request.form.get("username"),)

        #  read data from database
        crud.execute('SELECT id, username, hash FROM users WHERE username=?', uname)
        user = crud.fetchone()

        # Ensure username & password were registered on database a
        if not user or not check_password_hash(user["hash"], request.form.get("oldpass")):
            return apology("Invalid Username and/or Password!")

        # change the password and redirectuser to login page
        db_array = (generate_password_hash(request.form.get("newpass")), user["id"])
        crud.execute('UPDATE users SET hash=? WHERE id=?', db_array)
        db.commit()

        return redirect("/")

    # Load change_pass page if user asked
    else:

        # log out user before changing password (in case user conduct changing password via url)
        session.clear()

        return render_template("chpass.html")


@app.route("/deposit", methods=["GET", "POST"])
@login_required
def deposit():
    """ deposit more money in user account """

    if request.method == "POST":

        # Ensure deposit amount was submitted and is according correct format (greater than zero and not more than two point float)
        if not request.form.get("deposit") or float(request.form.get("deposit")) <= 0:
            return apology("Invalid Amount (example: 123.08)")

        # read user current cash from database
        uid = (session["user_id"],)
        crud.execute('SELECT cash FROM users WHERE id=?', uid)
        cash = crud.fetchone()["cash"]

        # deposit amount and update user current cash
        db_array = (cash + float("{:.2f}".format(float(request.form.get("deposit")))), session["user_id"],)
        crud.execute('UPDATE users SET cash=? WHERE id=?', db_array)
        db.commit()

        # write deposit amount into database
        deposit = (session["user_id"], float("{:.2f}".format(float(request.form.get("deposit")))),)
        crud.execute('INSERT INTO deposit (user_id, amount) VALUES (?, ?)', deposit)
        db.commit()

        # send feedback to user
        flash("{} Deposited!".format(usd(float("{:.2f}".format(float(request.form.get("deposit")))))))
        return redirect("/")

    else:
        return render_template("deposit.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
