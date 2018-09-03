from flask import Flask, render_template, flash, redirect, session, url_for, logging, request
from passlib.hash import sha256_crypt
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'signin'
login_manager.login_message_category = "danger"

SESSION_COOKIE_SECURE = True
REMEMBER_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
REMEMBER_COOKIE_HTTPONLY = True

#Configure SQLAlchemy

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///D:\\FlaskApp\\database\\flask.db'

#Initialize SQLAlchemy
db = SQLAlchemy(app)

class User(UserMixin, db.Model):
	id = db.Column(db.INTEGER, primary_key=True)
	name = db.Column(db.String(25))
	email = db.Column(db.String(50), unique=True)
	password = db.Column(db.String(80))

@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))

@app.route('/')
def index():
	return render_template('index.html')

@app.route('/signin', methods=['GET','POST'])
def signin():
	if request.method == 'POST':
		emailin = request.form['email']
		passin = request.form['password']

		result = User.query.filter_by(email=emailin).first()

		if result:
			password = result.password
			user = result.name
			rem = bool(len(request.form.getlist("remember_me")))

			if sha256_crypt.verify(passin, password):
				#Create session
				login_user(result, remember=rem)
				return redirect(url_for('home'))
			else:
				error = 'Password Incorrect'
			return render_template('signin.html', error=error)
			cur.close()
		else:
			error = 'Email not found'
			return render_template('signin.html', error=error)

	return render_template('signin.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
	if request.method == 'POST':
		name = request.form['name']
		email = request.form['email']
		password = sha256_crypt.encrypt(request.form['password'])
		confirm = sha256_crypt.encrypt(request.form['confirm_password'])

		new_user = User(name=name, email=email, password=password)
		db.session.add(new_user)
		db.session.commit()
		flash("SignUp successful", 'success') 
		
		return redirect(url_for('signin'))
	return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
	logout_user()
	return redirect(url_for('index'))

@app.route('/home')
@login_required
def home():
	return render_template('home.html')
	
if __name__ == '__main__':
	app.secret_key=os.urandom(16)
	app.run(debug=True, host='0.0.0.0')