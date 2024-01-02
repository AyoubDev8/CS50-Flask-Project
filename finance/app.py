import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

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
    # Retrieve user's portfolio
    stocks = db.execute(
        "SELECT symbol, name, price, SUM(shares) as total_shares FROM transactions WHERE user_id = ? GROUP BY symbol",
        session["user_id"]
    )
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

    total = cash
    for stock in stocks:
        total += stock["price"] * stock["total_shares"]

    return render_template("index.html", stocks=stocks, cash=cash, usd=usd, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
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
        except ValueError:
            return apology("must provide valid number of shares")
        if shares <= 0:
            return apology("shares must be a positive integer")

        # Get user's cash
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        item_name = item["name"]
        item_price = item["price"]
        total_price = item_price * shares

        # Check if the user can afford the purchase
        if total_price > cash:
            return apology("You can't afford this", 400)
        else:
            # Update user's cash
            db.execute("UPDATE users SET cash = ? WHERE id = ?", cash - total_price, session["user_id"])

            # Record the transaction
            db.execute("INSERT INTO transactions (user_id, name, shares, price, type, symbol) VALUES (?, ?, ?, ?, ?, ?)",
                       session["user_id"], item_name, shares, item_price, "buy", symbol)

            flash("Bought!")
            return redirect("/")
    else:
        # Render the template for buying stocks
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # Retrieve user's transaction history
    transactions = db.execute("SELECT symbol, price, time, shares FROM transactions WHERE user_id = ?", session["user_id"])
    return render_template("history.html", transactions=transactions, usd=usd)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    # Forget any user_id
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Ensure username and password were submitted
        if not username or not password:
            return apology("must provide username and password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")
    else:
        # Render the login template for GET requests
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
        # Ensure name of stock was submitted
        symbol = request.form.get("symbol").upper()

        if not symbol:
            return apology("must provide stock symbol")

        # Use the lookup function
        stock = lookup(symbol)

        # Check if stock is valid
        if stock:
            return render_template("quote.html", stock=stock)
        else:
            return apology("Stock symbol not valid", 400)
    else:
        # Render the template for getting a stock quote
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Forget any user_id
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure username, password, and confirmation were submitted
        if not username or not password or not confirmation:
            return apology("must provide username, password, and confirmation", 400)

        # Ensure passwords match
        if password != confirmation:
            return apology("passwords must match", 400)

        # Check if username already exists in the database
        existing_user = db.execute("SELECT * FROM users WHERE username = ?", username)
        if existing_user:
            return apology("Username already exists", 400)

        # Add the new user to the database
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, generate_password_hash(password))

        # Log in the new user
        new_user = db.execute("SELECT id FROM users WHERE username = ?", username)
        session["user_id"] = new_user[0]["id"]

        flash("Registered!")
        return redirect("/")
    else:
        # Render the registration template for GET requests
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        shares = int(request.form.get("shares"))

        # Ensure stock and shares were submitted
        if not symbol:
            return apology("must provide symbol")
        if not shares or shares <= 0:
            return apology("must provide valid number of shares")

        # Get information about the stock
        item = lookup(symbol)
        item_name = item["name"]
        item_price = item["price"]
        total_sold = shares * item_price

        # Check if the user has enough shares to sell
        shares_owned = db.execute("SELECT * FROM transactions WHERE user_id = ? and symbol = ? GROUP BY symbol",
                                  session["user_id"], symbol)[0]["shares"]
        if shares > shares_owned:
            return apology("You don't have enough shares")

        # Update user's cash
        old_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        db.execute("UPDATE users SET cash = ? WHERE id = ?", old_cash + total_sold, session["user_id"])

        # Record the transaction
        db.execute("INSERT INTO transactions (symbol, name, shares, price, type, user_id) VALUES (?, ?, ?, ?, ?, ?)",
                   symbol, item_name, -shares, item_price, "Sell", session["user_id"])

        flash("Sold!")
        return redirect("/")
    else:
        # Render the template for selling stocks
        symbols = db.execute("SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol", session["user_id"])
        return render_template("sell.html", symbols=symbols)
