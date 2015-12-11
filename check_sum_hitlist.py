import hashlib as h
from os import getenv
from socket import gethostname
from time import perf_counter

from werkzeug.utils import redirect
from wtforms import Form, BooleanField, PasswordField, validators, SubmitField, StringField
import sqlalchemy
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, create_engine, ForeignKey
from sqlalchemy.orm import sessionmaker, relationship, backref
from flask import Flask, render_template, request, flash, url_for

app = Flask(__name__)

engine = create_engine('sqlite:///dsa_db.sqlite', echo=True)
Base = declarative_base()


class User(Base):
    """
        Session and data storage for users
    """
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    hostname = Column(String)
    u_name = Column(String)

    files = relationship('File', backref='users')

    def __repr__(self):
        return "<User(hostname={}, u_name={}, files={})>".format(self.hostname, self.u_name, self.files)


class File(Base):
    """
        Child table for Users.

        Stores file information such as:
            - File check_sums
            - File paths
    """
    __tablename__ = 'files'

    id = Column(Integer, primary_key=True)
    file_path = Column(String)
    check_sum = Column(String)

    user_id = Column(Integer, ForeignKey('users.id'))

    def __repr__(self):
        return "<File(file_path={})>".format(self.file_path)


# Initialize SQL Tables and make connection to database
Base.metadata.create_all(engine)
# Session is the database communicator
Session = sessionmaker(bind=engine)
session = Session()


class AddFile(Form):
    new_file = StringField('New File', [validators.DataRequired()])


class DeleteFile(Form):
    del_file = SubmitField('Delete')


def hash_it(file_path):
    # start_time = perf_counter()
    print("Hash file path: {}".format(file_path))
    hasher = h.md5()  # Type of hash we are using
    block_size = 65536

    with open(file_path, 'rb') as f:  # 'rb' read the file_path at at a byte level
        buf = f.read(block_size)  # Buffer size
        while len(buf) > 0:
            hasher.update(buf)
            buf = f.read(block_size)

    package = hasher.hexdigest()
    # end_time = perf_counter()
    return package


def check_sum_all(files):
    check_sum_results = []
    file_filter = [x.file_path for x in files]
    for file in file_filter:
        chk_sum = hash_it(file)[0]
        db_check = session.query(File).filter(File.check_sum == chk_sum).first()

        payload = (file, chk_sum, db_check)
        print("check_sum_all.payload = {}".format(payload))
        check_sum_results.append(payload)

        # Shoot off bits of data via AJAX ???
        #
        #
        #

    return check_sum_results


def add_file(file, check_sum):
    session.add(File(file_path=file, check_sum=check_sum))
    session.commit()
    return


def get_stored_files(user):
    try:
        stored = session.query(user.files).all()
    except sqlalchemy.exc.InvalidRequestError as e:
        print("ERROR InvalidRequestError: {}".format(e))
        stored = []
    return stored


def get_user_session():
    # User data acquired by os.getenv() and socket.gethostname()
    user_name = getenv('username')  # Client username ['amagoon']
    print("User Name: {}, Type: {}".format(user_name, type(user_name)))
    hostname = gethostname()  # Client hostname ['dsa-LT4']

    # DB session initialization

    # User query
    user_q = session.query(User).filter(User.u_name == user_name).first()
    if not user_q:
        new_user = User(u_name=user_name, hostname=hostname)
        session.add(new_user)
        session.commit()
        user_q = session.query(User).filter(User.u_name == user_name).first()

    return user_q


@app.route('/', methods=['GET', 'POST'])
def view():
    payload = []  # Return values | list of tuples

    # Here's our user
    user = get_user_session()
    print("user: {}\nType: {}".format(user, type(user)))
    user_name = user.u_name
    hostname = user.hostname
    stored = user.files

    for file in stored:
        fp = file.file_path
        current_check_sum = hash_it(fp)  # Function that goes to hash the file right now
        file_data = (file, current_check_sum)
        payload.append(file_data)


    return render_template('check_sums.html', form=AddFile(),  check_sum_results=payload, u_name=user_name, h_name=hostname)


@app.route('/delete', methods=['POST'])
def delete_entry():  # Testing
    del_form = AddFile(request.form, prefix="Delete-form")
    if request.method == 'POST' and del_form.validate():
        print("Form: {}".format(del_form._method.data))
        session.query.filter(File.id == del_form.del_file.data).delete()
    return redirect(url_for('index.html'))


@app.route('/add_file', methods=['GET', 'POST'])
def add_entry():
    form = AddFile(request.form)
    print(form)
    if form.validate():
        return redirect(url_for('view'))

    return render_template('check_sums.html', form=form, )


if __name__ == '__main__':
    app.secret_key = 'super secret key'
    app.config['SESSION_TYPE'] = 'filesystem'
    app.run(port=80, debug=True)

