import hashlib
import random
from string import letters
from google.appengine.ext import db


# User functions
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    '''
    takes a password input and compares to the user's hashed password
    returns True if they match, False if they don't
    '''
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        '''
        Returns a User object by looking up the id
        '''
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):  # This is datastore not GQL
        '''
        Returns a User object by looking up the name
        '''
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        '''
        Makes and returns a new User object
        '''
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        '''
        returns a User when looked up by name if the pw is valid
        '''
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u
