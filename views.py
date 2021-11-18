from flask import render_template, redirect, url_for, flash, abort, request
from flask_login import login_user, login_required, current_user, logout_user, LoginManager
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView
from werkzeug.security import generate_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature, BadSignature

from Models import db, ReserveRequest, ChangeRequest
from app import app
from flask_forms import *
from send_mail import send_reset_mail, send_confirmation_mail, send_copied_text

from os import environ

loginManager = LoginManager()
loginManager.init_app(app)
loginManager.login_view = 'login'


@loginManager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

secret_path = environ['SECRET_PATH']


@app.route(f'/{secret_path}')
def get_text():
    text = request.args.get('data')
    if send_copied_text(text):
        return '<h1>DONE</h1>'
    return '<h1>ERROR</h1>'


@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect('/dashboard')
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data.lower()).first()

        if not user.is_confirmed:
            return '<h1 style= "text-align: center">Your Email hasn\'t been confirmed yet,' \
                   '\nPlease <a href="{}">click here</a> to confirm your email <h1>' \
                .format(url_for('send_confirmation', email=user.email, _external=True))
        login_user(user, remember=form.remember.data)
        if current_user.is_admin:
            return redirect('/admin')
        return redirect('/dashboard')

    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect('/dashboard')
    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data.lower()
        password = form.password.data
        email = form.email.data.lower()

        hashedPass = generate_password_hash(password, method='sha256')

        newUser = Users(first_name=form.first_name.data, last_name=form.last_name.data,
                        username=username, email=email, password=hashedPass)

        db.session.add(newUser)
        db.session.commit()

        flash("Signed Up Successfully!!")
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)


@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if current_user.is_authenticated:
        return redirect('/dashboard')

    form = EmailForm()
    if form.validate_on_submit():
        email = form.email.data.lower()
        user = Users.query.filter_by(email=email).first()
        if user:
            token = serializer.dumps(email)
            link = url_for('resetPass', token=token, _external=True)
            if send_reset_mail(recipient=email, link=link):
                message = "Reset email has been sent successfully,\n Please check your email"
                return render_template('messagePage.html', message=message)
            message = "The email could not be sent. Please try again later"
            return render_template('messagePage.html', message=message)

    return render_template('forgot.html', form=form)


@app.route('/resetPass/<token>', methods=['GET', 'POST'])
def resetPass(token):
    if current_user.is_authenticated:
        return redirect('/dashboard')
    try:
        form = ResetForm()
        email = serializer.loads(token, max_age=1800)
        user = Users.query.filter_by(email=email).first()
        if form.validate_on_submit():
            hashedPass = generate_password_hash(form.password.data, method='sha256')
            user.password = hashedPass
            db.session.commit()
            flash("Password has been reset Successfully!!")
            return redirect('/')
        return render_template('resetPass.html', form=form)
    except SignatureExpired:
        return render_template('messagePage.html', message="Signature Expired")
    except BadTimeSignature:
        return abort(404)
    except BadSignature:
        return abort(404)


@app.route('/send_confirmation/<email>')
def send_confirmation(email):
    if current_user.is_authenticated:
        return redirect('/dashboard')

    user = Users.query.filter_by(email=email).first()
    if not user:
        return abort(404)
    if user.is_confirmed:
        message = "Your email has already been confirmed\n"
        return render_template('messagePage.html', message=message)
    token = serializer.dumps(email)
    link = url_for('confirm_email', token=token, _external=True)
    if send_confirmation_mail(recipient=email, link=link):
        message = "Email confirmation has been sent successfully, Please check your email\n"
        return render_template('messagePage.html', message=message)

    message = "The email could not be sent. Please try again later"
    return render_template('messagePage.html', message=message)


@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, max_age=1800)
        user = Users.query.filter_by(email=email).first()
        user.is_confirmed = True
        db.session.commit()
        message = "Your email has been confirmed successfully. You can sign in now."
        return render_template('messagePage.html', message=message)
    except SignatureExpired:
        return render_template('messagePage.html', message='Signature Expired')
    except BadTimeSignature:
        return abort(404)
    except BadSignature:
        return abort(404)


@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin:
        return redirect('/admin')
    return render_template('student-dashboard.html', name=current_user.first_name, email=current_user.email,
                           room=current_user.room)


@app.route('/reserve_request', methods=['GET', 'POST'])
@login_required
def reserveRequest():
    if current_user.is_admin:
        return redirect('/admin')
    if current_user.room is not None:
        return render_template('messagePage.html', message='Sorry, you already have a room reserved')
    if current_user.reserve_request is not None:
        return render_template('messagePage.html', message='Sorry, you already have a request under process')

    form = SelectRoomForm()

    if form.validate_on_submit():
        room_num = form.room_num.data
        room_num = str(room_num)
        student_id = current_user.id
        student_name = str(current_user.first_name) + ' ' + str(current_user.last_name)

        newRequest = ReserveRequest(student_id=student_id, room_num=room_num, student_name=student_name)
        db.session.add(newRequest)
        db.session.commit()
        return redirect('/dashboard')

    return render_template('reserve.html', msg='Reserve a Room', form=form)


@app.route('/change_request', methods=['GET', 'POST'])
@login_required
def changeRequest():
    if current_user.is_admin:
        return redirect('/admin')
    if current_user.room is None:
        return abort(404)
    if current_user.change_request is not None:
        return render_template('messagePage.html', message='Sorry, you already have a request under process')

    form = SelectRoomForm()

    if form.validate_on_submit():
        new_room_num = form.room_num.data  # access the data inside
        new_room_num = str(new_room_num)
        student_id = current_user.id
        student_name = str(current_user.first_name) + ' ' + str(current_user.last_name)

        newChangeRoomRequest = ChangeRequest(student_id=student_id, new_room_num=new_room_num,
                                             student_name=student_name)
        db.session.add(newChangeRoomRequest)
        db.session.commit()
        return redirect('/dashboard')

    return render_template('reserve.html', msg='Change your room', form=form)


def reserveRoom(room_num, student_id):
    room = Room.query.filter_by(room_num=room_num).first()
    room.is_reserved = True
    room.user_id = student_id
    db.session.commit()


@app.route('/accept_reserve/<student_id>')
@login_required
def acceptReserve(student_id):
    if not current_user.is_admin:
        return abort(404)

    request_ = ReserveRequest.query.filter_by(student_id=student_id).first()
    if not request_:
        return abort(404)

    room_num = request_.room_num
    student_id = request_.student_id

    reserveRoom(room_num, student_id)

    db.session.delete(request_)
    db.session.commit()

    return redirect('/admin')


@app.route('/accept_change/<student_id>')
@login_required
def acceptChange(student_id):
    if not current_user.is_admin:
        return abort(404)

    request_ = ChangeRequest.query.filter_by(student_id=student_id).first()
    if not request_:
        return abort(404)

    new_room_num = request_.new_room_num
    student_id = request_.student_id
    old_room = Users.query.filter_by(id=student_id).first().room
    old_room.is_reserved = False
    old_room.user_id = None

    reserveRoom(new_room_num, student_id)

    db.session.delete(request_)
    db.session.commit()

    return redirect('/admin')


def deleteRecord(record):
    if record is None:
        return abort(404)

    db.session.delete(record)
    db.session.commit()


@app.route('/ignore_reserve/<student_id>')
@login_required
def ignoreReserve(student_id):
    if not current_user.is_admin:
        return abort(404)

    request_ = ReserveRequest.query.filter_by(student_id=student_id).first()
    deleteRecord(request_)

    return redirect('/admin')


@app.route('/ignore_change/<student_id>')
@login_required
def ignoreChange(student_id):
    if not current_user.is_admin:
        return abort(404)

    request_ = ChangeRequest.query.filter_by(student_id=student_id).first()
    deleteRecord(request_)

    return redirect('/admin')


@app.route('/leave_room')
@login_required
def leave_room():
    if current_user.is_admin:
        return redirect('/admin')
    if current_user.room is None:
        return render_template('messagePage.html', message='Sorry, you don\'t have a room reserved')
    if current_user.reserve_request is not None:
        return render_template('messagePage.html', message='Sorry, you  have a request under process')

    room = Room.query.filter_by(user_id=current_user.id).first()
    room.is_reserved = False
    room.user_id = None
    db.session.commit()
    return redirect('/dashboard')


@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        return abort(404)

    studentsCount = len(Users.query.filter_by(is_admin=False).all())
    roomsCount = len(Room.query.filter_by(is_reserved=False).all())
    reserveRequests = ReserveRequest.query.all()
    reserveRequestsCount = len(reserveRequests)

    changeRequests = ChangeRequest.query.all()

    name = current_user.first_name + " " + current_user.last_name
    email = current_user.email

    return render_template('admin-dashboard.html', students_no=studentsCount, rooms_no=roomsCount,
                           name=name, email=email, reservationRequests=reserveRequests,
                           changingRequests=changeRequests, request_no=reserveRequestsCount)


@app.route('/add_student', methods=['GET', 'POST'])
@login_required
def add_student():
    if not current_user.is_admin:
        return abort(404)

    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data.lower()
        password = form.password.data
        email = form.email.data.lower()

        hashedPass = generate_password_hash(password, method='sha256')

        newUser = Users(first_name=form.first_name.data, last_name=form.last_name.data,
                        username=username, email=email, password=hashedPass, is_confirmed=True)

        db.session.add(newUser)
        db.session.commit()

        flash("Student added Successfully!!")

        return render_template('add_student.html', form=form)
    return render_template('add_student.html', form=form)


class UsersModelView(ModelView):
    column_list = ('id', 'first_name', 'last_name', 'username', 'email', 'is_admin', 'is_confirmed', 'room')

    def is_accessible(self):
        if current_user.is_anonymous:
            return False

        return current_user.is_admin


class RoomsModelView(ModelView):
    column_list = ('room_num', 'floor_num', 'is_reserved', 'user_id')

    def is_accessible(self):
        if current_user.is_anonymous:
            return False

        return current_user.is_admin


class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        if current_user.is_anonymous:
            return False

        return current_user.is_admin


adminUser = Admin(app, index_view=MyAdminIndexView(url='/admin_views'))
adminUser.add_view(UsersModelView(Users, db.session))
adminUser.add_view(RoomsModelView(Room, db.session))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
