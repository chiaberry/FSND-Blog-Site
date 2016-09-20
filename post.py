import os
import jinja2

from google.appengine.ext import db

from user import User

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    author = db.StringProperty()
    likes = db.IntegerProperty()
    likers = db.StringListProperty()
    comment_count = db.IntegerProperty()

    def getAuthorName(self):
        user = User.by_id(self.author)
        return user.name

    def render_post(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)
