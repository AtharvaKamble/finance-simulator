import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# pk_477b59fe76664974b081c6d679ae5e6b

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
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    if request.method == "GET":
        # Query 'current' table for user's stocks' info
        row_current = db.execute("SELECT * FROM current WHERE owner = ?", session["user_id"])
        # print("DEBUUUUUUUUUU", row_current)
        total = 0
        for i in row_current:
            total += i['total']

        # Query 'users' table for users' cash info
        cash = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

        return render_template("portfolio.html", rows=row_current, total=total, cash=cash[0])
    return apology("ERROR IN INDEX")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        # Check whether user has entered stock symbol to buy or not
        if not request.form.get("symbol"):
            return apology("Enter stock symbol to buy")

        # current user info
        user_info = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

        # use lookup function to make request to API
        stock_info = lookup(request.form.get("symbol"))

        # Buy stocks so long as the user affords it
        if user_info[0]['cash'] - stock_info['price'] * int(request.form.get("shares")) <= 0:
            return apology("Not enough funds")
        else:
            new_cash = user_info[0]['cash'] - (stock_info['price'] * int(request.form.get("shares")))
            db.execute("UPDATE users SET cash = ? WHERE id = ?", new_cash, session["user_id"])

        # Current date-time
        now = datetime.now()
        dt_curr = now.strftime("%Y-%m-%d %H:%M:%S")

        current_state = int(request.form.get("shares"))

        # Query 'history' table to INSERT bought stocks
        db.execute("INSERT INTO history (stockid, stockName, stockSym, stockPrice, stockTotal, createdAt, state) VALUES (?, ?, ?, ?, ?, ?, ?)", session["user_id"], stock_info['name'], stock_info['symbol'], stock_info['price'], stock_info['price'] * int(request.form.get("shares")), dt_curr, current_state)


        # Unique ID to store everyone
        UNI_id = str(session["user_id"]) + str(stock_info['symbol'])

        # Query 'current' table to UPDATE bought stocks
        row_current = db.execute("SELECT * FROM current WHERE sym_id = ?", UNI_id)
        # print("DEBUGBUGB -> ", row_current)
        if len(row_current) == 0:
            db.execute("INSERT INTO current (owner, sym_id, name, sym, amount, price, total) VALUES (?, ?, ?, ?, ?, ?, ?)", session['user_id'], UNI_id, stock_info['name'], stock_info['symbol'], current_state, stock_info['price'], current_state * stock_info['price'])
        else:
            hist_data = db.execute("SELECT * FROM history WHERE stockid = ? AND stockSym = ?", session["user_id"], stock_info['symbol'])
            new_amount = int(row_current[0]['amount']) + current_state
            new_price = stock_info['price']
            new_total = int(row_current[0]['total']) + (current_state * stock_info['price'])
            db.execute("UPDATE current SET amount = ?, price = ?, total = ? WHERE sym_id = ?", new_amount, new_price, new_total, UNI_id)

        return redirect("/")
    else:
        return render_template("buy.html")
    return apology("ERROR IN BUY")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    if request.method == "GET":
        row_current = db.execute("SELECT * FROM history WHERE stockid = ?", session["user_id"])
        print(row_current)
        return render_template("history.html", rows=row_current)

    return apology("ERROR IN HISTORY")


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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

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
        # Check whether user has entered stock symbol or not
        if not request.form.get("quote"):
            return apology("Enter stock symbol to check")

        info = lookup(request.form.get("quote"))
        print(info)
        return render_template("quote_res.html", stock=info)
    else:
        return render_template("quote.html")

    return apology("ERROR IN QUOTE")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Ensure password is checked
        elif not request.form.get("confirm-password"):
            return apology("must confirm password", 403)

        # Check if password is confirmed or not
        if request.form.get("password") != request.form.get("confirm-password"):
            return apology("enter correct password", 403)

        # Credentials to be inserted in database
        name = request.form.get("username")
        password = generate_password_hash(request.form.get("password"))

        # Query database to insert new name, password
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", name, password)

        # current person's id
        current_id = db.execute("SELECT id FROM users WHERE username = ?", name)

        # Remember which user has logged in
        session["user_id"] = current_id[0]['id']

        # After successful insertion of data, redirect to default page
        return redirect("/")

    else:
        return render_template("register.html")
    return apology("ERROR IN REGISTER")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        # Check whether user has entered stock symbol to sell or not
        if not request.form.get("symbol"):
            return apology("Enter stock symbol to sell")
        if not request.form.get("shares"):
            return apology("Enter how many shares to sell")

        # Lookup for price
        stock_info = lookup(request.form.get("symbol"))

        # Current date-time
        now = datetime.now()
        dt_curr = now.strftime("%Y-%m-%d %H:%M:%S")

        # Unique identifier for all records
        UNI_id = str(session["user_id"]) + str(stock_info['symbol'])
        # print("______> ", UNI_id)

        # Query 'current' table to check if user owns stocks to sell or not
        row = db.execute("SELECT * FROM current WHERE sym_id = ?", UNI_id)

        # print("DEB------> ", row)
        if len(row) == 0:
            return apology("No stocks found")

        # Query 'current' table to update the amount, total
        new_current_state = int(row[0]['amount']) + int(request.form.get("shares")) * (-1)
        new_total = int(row[0]['total']) - (int(request.form.get("shares")) * stock_info['price'])
        print("____________________>", new_current_state, new_total)

        # Check if stocks are null and report accordingly
        if new_current_state < 0:
            return apology("Not enough stocks to sell")

        # Query 'history' table to INSERT record of transaction
        db.execute("INSERT INTO history (stockid, stockName, stockSym, stockPrice, stockTotal, createdAt, state) VALUES (?, ?, ?, ?, ?, ?, ?)", session["user_id"], stock_info['name'], stock_info['symbol'], stock_info['price'], (int(request.form.get("shares")) * stock_info['price']), dt_curr, int(request.form.get("shares")) * (-1))

        # Query 'users' table to update user's cash
        user_info = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        user_cash = user_info[0]['cash']
        db.execute("UPDATE users SET cash = ? WHERE id = ?", user_cash + (int(request.form.get("shares")) * stock_info['price']), session["user_id"])

        # Query 'current' to UPDATE user's amount, total
        db.execute("UPDATE current SET amount = ?, total = ? WHERE sym_id = ?", new_current_state, new_total, UNI_id)

        if new_current_state == 0:
            db.execute("DELETE FROM current WHERE sym_id = ?", UNI_id)

        return redirect("/")
    else:
        # Query 'current' table to get symbol names
        row_current = db.execute("SELECT * FROM current WHERE owner = ?", session["user_id"])
        return render_template("sell.html", rows=row_current)
    return apology("ERROR IN SELL")


@app.route("/password", methods=["GET", "POST"])
@login_required
def password_change():
    """Change password"""
    if request.method == "POST":
        # Check whether user has entered new password or not
        if not request.form.get("new-password"):
            return apology("Enter new password")
        if not request.form.get("confirm-password"):
            return apology("Re-enter new password")
        if request.form.get("new-password") != request.form.get("confirm-password"):
            return apology("Re-enter error")

        # Query 'users' table to UPDATE password
        new_password = generate_password_hash(request.form.get("new-password"))
        db.execute("UPDATE users SET hash = ? WHERE id = ?", new_password, session["user_id"])

        return render_template("password_changed.html")
    else:
        return render_template("password_change.html")
    return apology("ERROR IN PASSWORD CHANGE")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
