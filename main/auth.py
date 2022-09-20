import functools
import re

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from main.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        last_name = request.form['last_name']
        first_name = request.form['first_name']
        password_confirm = request.form['password_confirm']
        db = get_db()
        error = None

        if not re.match(r"^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$", email, re.I):
            error = 'Email is not valid.'
        elif not re.match(r'[A-Za-z0-9@#$%^&+=]{8,}', password):
            error = 'Password is not valid.'
        elif not last_name:
            error = 'Last name is not valid'
        elif not first_name:
            error = 'First name is not valid'
        elif not password == password_confirm:
            error = 'Passwords do not match'

        def generate_salt():
            import random
            return '%030x' % random.randrange(16**30)

        if error is None:
            try:
                salt = generate_salt()
                db.execute(
                    "INSERT INTO user (email, password, first_name, last_name, salt) VALUES (?, ?, ?, ?, ?)",
                    (email, generate_password_hash(password + salt), first_name, last_name, salt),
                )
                db.commit()
            except db.IntegrityError:
                error = f"Email {email} is already registered."
            else:
                return redirect(url_for("auth.login"))

        flash(error)

    return render_template('auth/register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE email = ?', (email,)
        ).fetchone()

        if user is None:
            error = 'Incorrect email.'
        elif not check_password_hash(user['password'], password + user['salt']):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('user.index'))

        flash(error)

    return render_template('auth/login.html')

@bp.route('/logout', methods=('GET', 'POST'))
def logout():
    session.clear()
    return redirect(url_for('index'))
    
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view