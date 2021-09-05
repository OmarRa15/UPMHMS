from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length, EqualTo, ValidationError
from werkzeug.security import check_password_hash
from wtforms_sqlalchemy.fields import QuerySelectField

from Models import Users, Room


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

    def validate_username(self, username):
        user = Users.query.filter_by(username=username.data.lower()).first()

        if not user:
            raise ValidationError('incorrect username or password')
        if not check_password_hash(user.password, self.password.data):
            raise ValidationError('incorrect username or password')


class EmailForm(FlaskForm):
    email = StringField('Enter Your email',
                        validators=[InputRequired(), Email(message='Invalid email', check_deliverability=True),
                                    Length(max=50)])

    def validate_email(self, email):
        user = Users.query.filter_by(email=email.data.lower()).first()

        if not user:
            raise ValidationError('email doesn\'t exists')


class ResetForm(FlaskForm):
    password = PasswordField('New Password', validators=[InputRequired(), Length(min=8, max=80),
                                                         EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Confirm_password', validators=[InputRequired(), Length(min=8, max=80)])


class RegisterForm(FlaskForm):
    # email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email', check_deliverability=True),
    #                                          Length(max=50)])
    email = StringField('Email', validators=[InputRequired(),
                                             Length(max=50)])

    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80),
                                                     EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Confirm_password', validators=[InputRequired(), Length(min=8, max=80)])
    first_name = StringField('First Name', validators=[InputRequired(), Length(min=3, max=20)])
    last_name = StringField('Last Name', validators=[InputRequired(), Length(min=3, max=20)])

    def validate_username(self, username):
        user = Users.query.filter_by(username=username.data.lower()).first()

        if user:
            raise ValidationError('User already exists')

    def validate_email(self, email):
        user = Users.query.filter_by(email=email.data.lower()).first()

        if user:
            raise ValidationError('email already exists')


def rooms_query():
    return Room.query.filter_by(is_reserved=False, change_request=None, reserve_request=None)


class SelectRoomForm(FlaskForm):
    room_num = QuerySelectField(query_factory=rooms_query, allow_blank=False, get_label='room_num')
