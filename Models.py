from flask_login import UserMixin

from app import db


class Users(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(20))
    last_name = db.Column(db.String(20))
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(255))
    is_admin = db.Column(db.Boolean, default=False)
    is_confirmed = db.Column(db.Boolean, default=False)

    room = db.relationship('Room', backref='users', uselist=False)
    reserve_request = db.relationship('ReserveRequest', backref='users', uselist=False)
    change_request = db.relationship('ChangeRequest', backref='users', uselist=False)

    def __repr__(self):
        return 'ID: ' + str(self.id) + ' ' + self.first_name + ' ' + self.last_name


class Room(db.Model):
    room_num = db.Column(db.Integer, primary_key=True)
    floor_num = db.Column(db.Integer)
    is_reserved = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True)

    reserve_request = db.relationship('ReserveRequest', backref='room', uselist=False)
    change_request = db.relationship('ChangeRequest', backref='room', uselist=False)

    def __repr__(self):
        return str(self.room_num)


class ReserveRequest(db.Model):
    student_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, primary_key=True)
    room_num = db.Column(db.Integer, db.ForeignKey('room.room_num'), unique=True)
    student_name = db.Column(db.String(20))


class ChangeRequest(db.Model):
    student_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, primary_key=True)
    new_room_num = db.Column(db.Integer, db.ForeignKey('room.room_num'), unique=True)
    student_name = db.Column(db.String(20))
