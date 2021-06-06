from flask import Flask
from flask_bootstrap import Bootstrap
from os import environ

app = Flask(__name__)
app.config['SECRET_KEY'] = environ['SECRET_KEY']
app.config['SQLALCHEMY_DATABASE_URI'] = environ['DATABASE_URL'][0:8] + 'ql' + environ['DATABASE_URL'][8:]

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

Bootstrap(app)
# db = SQLAlchemy(app)


from views import *

if __name__ == '__main__':
    app.run()
