from flask import (
    Blueprint, g, redirect, render_template, request, url_for, flash
)
from werkzeug.security import check_password_hash

from main.auth import login_required
from main.db import get_db

bp = Blueprint('user', __name__, url_prefix='/user')

@bp.route('/', methods=('GET', 'POST'))
@login_required
def index():
    return render_template('user/index.html', user=g.user)

@bp.route('/update', methods=('GET', 'POST'))
@login_required
def update():
    if request.method == 'POST':
        if check_password_hash(g.user['password'], request.form['password'] + g.user['salt']):
            db = get_db()
            first_name = request.form['first_name']
            last_name = request.form['last_name']
            db.execute(
                'UPDATE user SET first_name = ?, last_name = ? WHERE id = ?',
                (first_name, last_name, g.user['id'])
            )
            db.commit()
            return redirect(url_for('user.index'))
        else:
            flash('Incorrect password')
    return render_template('user/update.html', user=g.user)

@bp.route('/delete', methods=('GET', 'POST'))
@login_required
def delete():
    db = get_db()
    db.execute(
        'DELETE FROM user WHERE id = ?',
        (g.user['id'],)
    )
    db.commit()
    return redirect(url_for('index'))
