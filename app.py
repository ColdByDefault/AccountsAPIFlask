""" Directory structure:
accountsAPI/
│   app.py
└───templates/
    │   register.html
    │   login.html
    │   index.html
 """


from flask import Flask, render_template, request, redirect, url_for, flash # pip install Flask
from flask_sqlalchemy import SQLAlchemy # pip install SQLAlchemy
import bcrypt # hash Passwords (pip install bcrypt)


# Create Flask App
app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite3'
db = SQLAlchemy(app)

# Connect to Database 
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(72), nullable=False)

# Username length valid
def username_valid(new_username):
    if len(new_username) < 5:
        flash("Username must be at least 5 characters!")
        return False
    elif len(new_username) > 12:
        flash("Username can NOT be longer than 12 characters!")
        return False
    else:
        return True

# Password conditions valid
def password_valid(new_password):
    if len(new_password) < 8:
        flash("Password must be at least 8 characters!")
        return False
    elif len(new_password) > 15:
        flash("Password must be less than 16 characters!")
        return False
    else:
        symbols_list = "!§$%&/()*@€#'_-.;,?"
        is_lower = any(character.islower() for character in new_password)
        is_upper = any(character.isupper() for character in new_password)
        has_symbol = any(character in symbols_list for character in new_password)
        is_digit = any(character.isdigit() for character in new_password)

        if is_lower and is_upper and has_symbol and is_digit:
            return True
        else:
            flash("Password must include numbers, at least one uppercase letter, and one special symbol!") 
            return False


# Home Page Render
@app.route('/')
def index():
    return render_template('index.html')

# Register End-Point register.html
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        new_username = request.form['username']
        new_password = request.form['password']
        conf_password = request.form['conf_password']

        if not username_valid(new_username) or not password_valid(new_password):
            return redirect(url_for('register'))

        if new_password != conf_password:
            flash("Passwords don't match.")
            return redirect(url_for('register'))

        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        if User.query.filter_by(username=new_username).first():
            flash('Username already exists.')
            return redirect(url_for('register'))

        new_user = User(username=new_username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('User created successfully!')
        return redirect(url_for('login'))
    return render_template('register.html')


# Login End-Point login.html
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.checkpw(password, user.password.encode('utf-8')):
            flash('Logged in successfully!')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')


# Logout Function
@app.route('/logout')
def logout():
    flash('You were logged out.')
    return redirect(url_for('index'))


# Run
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

