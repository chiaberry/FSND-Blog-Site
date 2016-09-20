from google.appengine.ext import db

from user import User


class Comment(db.Model):
    content = db.TextProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    user_id = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    def getUserName(self):
        user = User.by_id(self.user_id)
        return user.name
