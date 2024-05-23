import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd
from datetime import datetime

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # Get user info and stocks owned
    user = db.execute("SELECT * FROM users WHERE id=?", session["user_id"])
    owned = db.execute(
        "SELECT * FROM StocksOwned WHERE OwnerId = ?", session["user_id"])
    total = 0
    # get the current price for the stocks owned and calculate total value
    for i in range(len(owned)):
        stats = lookup(owned[i]["Symbol"])
        owned[i]["price"] = stats["price"]
        owned[i]["TotalValue"] = float(
            stats["price"])*float(owned[i]["TotalShares"])
    for n in owned:
        total = total+n["TotalValue"]
    return render_template("index.html", owned=owned, user=user[0], total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        # get the symbol to buy and check valaidity
        stocks = lookup(request.form.get("symbol"))
        if stocks == None:
            return apology("Invalid Symbol")
        # get shares and check validity
        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("Invalid shares")
        if shares < 0:
            return apology("Cannot Buy negative stocks")
        # after verification of input proceed to buying
        else:
            # get the cash the user has and turn to integer
            cash = db.execute(
                "SELECT cash FROM users WHERE id = ?", session["user_id"])
            # convert price to integer and how much cash is needed
            cash = float(cash[0]["cash"])
            price = float(stocks["price"])*shares
            # calculate remaining cash
            cash = cash-price
            if cash < 0:
                return apology("Not enough cash")
            else:
                # update user cash
                db.execute("UPDATE users SET cash = ? WHERE id = ?",
                           cash, session["user_id"])
                # update users owned stock
                Owned = db.execute("SELECT * FROM StocksOwned WHERE OwnerID = ? AND Symbol = ?",
                                   session["user_id"], stocks["symbol"])
                if len(Owned) == 0:
                    db.execute("INSERT INTO StocksOwned (OwnerId, CompanyStocks, TotalShares, Symbol) VALUES(?,?,?,?)",
                               session["user_id"], stocks["name"], shares, stocks["symbol"])
                else:
                    db.execute("UPDATE StocksOwned SET TotalShares=? WHERE OwnerID=? AND Symbol=?", shares + int(Owned[0]["TotalShares"]),
                               session["user_id"], stocks["symbol"])
                # log to history
                db.execute("INSERT INTO Transactions (OwnerID, Status, Symbol, Price, Shares, Date) VALUES(?,?,?,?,?,?)",
                           session["user_id"], "BUY", stocks["symbol"], price, shares, datetime.now())
                return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute(
        "SELECT * FROM  Transactions Where OwnerID = ? ORDER BY Date DESC", session["user_id"])
    return render_template("history.html", transactions=transactions)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?",
                          request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

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
    if request.method == "POST":
        results = lookup(request.form.get("symbol"))
        if results == None:
            return apology("Symbol Not Found")
        else:
            return render_template("quoted.html", results=results)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # get the inputs of the user
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        # validate the input
        if not username:
            return apology("Username Cannot be blank")
        if not password:
            return apology("Password cannot be blank")
        if not password == confirmation:
            return apology("Passwords do not match")
        check = db.execute(
            "SELECT username FROM users WHERE username = ?", username)
        if len(check) > 0:
            return apology("Username already exists")
        else:
            hash = generate_password_hash(password)
            db.execute(
                "INSERT INTO users (username,hash) VALUES(?, ?)", username, hash)
            return render_template("login.html")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("Select a Share")
        # get the user input
        stocks = lookup(request.form.get("symbol"))
        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("Invalid shares")
        # check if input is valid
        if shares < 0:
            return apology("Cannot sell negative shares")
        if stocks == None:
            return apology("Invalid Stocks")
        # attempt to sell(check if user has enough shares)
        owner = db.execute("SELECT * FROM StocksOwned WHERE OwnerID = ? AND Symbol = ?",
                           session["user_id"], stocks["symbol"])
        if len(owner) <= 0:
            return apology("You Dont Own the Stock")
        sold = int(owner[0]["TotalShares"])-shares
        if sold < 0:
            return apology("Not Enough Shares")
        # proceed with transaction
        else:
            # calculate the new cash of user
            price = float(stocks["price"])*float(shares)
            ownercash = db.execute(
                "SELECT cash FROM users WHERE id= ?", session["user_id"])
            newcash = float(ownercash[0]["cash"])+price
            # log to history
            db.execute("INSERT INTO Transactions (OwnerID, Status, Symbol, Price, Shares, Date) VALUES(?,?,?,?,?,?)",
                       session["user_id"], "SELL", stocks["symbol"], price, shares, datetime.now())
            # update values in database
            db.execute("UPDATE users SET cash = ? WHERE id = ?",
                       newcash, session["user_id"])
            db.execute("UPDATE StocksOwned SET TotalShares = ? WHERE OwnerID = ? AND Symbol = ?",
                       sold, session["user_id"], stocks["symbol"])
            return redirect("/")
    else:
        choices = db.execute(
            "SELECT * FROM StocksOwned WHERE OwnerID = ?", session["user_id"])
        return render_template("sell.html", choices=choices)


@app.route("/changepass", methods=["GET", "POST"])
@login_required
def changepass():
    if request.method == "POST":
        current = request.form.get("current")
        new = request.form.get("new")
        retype = request.form.get("retype")
        check = db.execute(
            "Select hash FROM users WHERE id =?", session["user_id"])
        if not check_password_hash(check[0]["hash"], current):
            return apology("Incorrect Password")
        if not new or not retype:
            return apology("New password cannot be empty")
        if not new == retype:
            return apology("Passwords do not match")
        else:
            new = generate_password_hash(new)
            db.execute("UPDATE users SET hash = ? WHERE id = ?",
                       new, session["user_id"])
            return render_template("changepass.html", status="Password Changed")
    else:
        return render_template("changepass.html")


@app.route("/deleteacc", methods=["GET"])
@login_required
def deleteacc():
    if request.method == "GET":
        db.execute("DELETE FROM Transactions WHERE OwnerID = ?",
                   session["user_id"])
        db.execute("DELETE FROM StocksOwned WHERE OwnerID = ?",
                   session["user_id"])
        db.execute("DELETE FROM users WHERE id = ?", session["user_id"])
        return redirect("/login")
