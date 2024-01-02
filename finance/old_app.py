import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from CS50_Intro.finance.old_helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


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
    # User is authenticated, show the index page
    stocks = db.execute(
        "SELECT symbol, name, price, SUM(shares) as total_shares FROM transactions WHERE user_id = ? GROUP BY symbol", session["user_id"])
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

    total = cash
    for stock in stocks:
        total += stock["price"] * stock["total_shares"]

    return render_template("index.html", stocks=stocks, cash=cash, usd=usd, total=total)


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        shares = int(request.form.get("shares"))
        symbol = request.form.get("symbol").upper()

        # Ensure stock was submitted
        if not symbol:
            return apology("must provide symbol")
        # Ensure shares was submitted
        if not shares:
            return apology("must provide shares")
        if shares <= 0:
            return apology("Shares must be positive")

        item = lookup(symbol)
        item_name = item["name"]
        item_price = item["price"]
        total_sold = shares * item_price

        shares_owned = db.execute("SELECT * FROM transactions WHERE user_id = ? and symbol = ? GROUP BY symbol",
                                  session["user_id"], symbol)[0]["shares"]

        if shares > shares_owned:
            return apology("You don't have enough shares")

        old_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        db.execute("UPDATE users SET cash = ? WHERE id = ?", old_cash + total_sold, session["user_id"])
        db.execute("INSERT INTO transactions (symbol, name, shares, price, type, user_id) VALUES (?, ?, ?, ?, ?, ?)",
                   symbol, item_name, -shares, item_price, "Sell", session["user_id"])

        # update the user_history
        flash("Sold!")
        return redirect("/")

    else:
        # User reaching via a GET method
        symbols = db.execute("SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol", session["user_id"])
        return render_template("sell.html", symbols=symbols)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        symbol = request.form.get("symbol").upper()
        item = lookup(symbol)
        # Ensure stock was submitted
        if not symbol:
            return apology("must provide symbol")
        elif not item:
            return apology("Invalid Symbol")

        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("must provide shares")
        if shares <= 0:
            return apology("shares must a positive int")

        # get cash
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

        item_name = item["name"]
        item_price = item["price"]
        total_price = item_price * shares

        if total_price > cash:
            return apology("You can't Afford", 400)
        else:
            db.execute("UPDATE users SET cash = ? WHERE id = ?", cash - total_price, session["user_id"])
            db.execute("INSERT INTO transactions (user_id, name, shares, price, type, symbol) VALUES (?, ?, ?, ?, ?, ?)",
                       session["user_id"], item_name, shares, item_price, "buy", symbol)
            flash("Bought!")
            return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute("SELECT symbol, price, time, shares FROM transactions WHERE user_id = ?", session["user_id"])
    return render_template("history.html", transactions=transactions, usd=usd)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

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


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)
        # Ensure password was confirmed
        elif not request.form.get("confirmation"):
            return apology("must provide password confirmation")
        # Ensure that passwords match
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords must match", 400)

        # Check if name already exists in the database
        users = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        if len(users) > 0:
            # If name already exists, send an appology
            return apology("Username already exists", 400)
        else:
            # add a new row in the users table
            db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", request.form.get(
                "username"), generate_password_hash(request.form.get("password")))
            # Retrieve the user ID for the new user
            user = db.execute("SELECT id FROM users WHERE username = ?", request.form.get("username"))
            # Store the user ID in the session
            session["user_id"] = user[0]["id"]
            flash("Registered!")
            return redirect("/")
    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure name of stock was submitted
        if not request.form.get("symbol"):
            return apology("must provide stock symbol")

        # Use the lookup function
        symbol = request.form.get("symbol").upper()
        stock = lookup(symbol)

        # Check if stock is valid
        if stock:
            return render_template("quote.html", stock=stock)

        # If its valid
        else:
            return apology("Stock symbol not valid", 400)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("quote.html")

