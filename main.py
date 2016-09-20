import os
import re
import random
import hmac
import time

from user import User
from comment import Comment
from post import Post

import jinja2
import webapp2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'telephony'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def checkUsername(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return username and USER_RE.match(username)


def checkPassword(password):
    PASS_RE = re.compile(r"^.{3,20}$")
    return password and PASS_RE.match(password)


def checkEmail(email):
    E_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
    return not email or E_RE.match(email)


def make_secure_val(val):
    '''
    Takes a value and returns a secure_val string containing
    the value and it's hash, separated by a pipe
    '''
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())
    # this is for the cookie


def check_secure_val(secure_val):
    '''
    Checks to see if the secure val is correct
    AKA the hash of the first half matches the second half
    if so, returns the val. else return Null
    '''
    val = secure_val.split('|')[0]
    # returns the first half the secure val
    if secure_val == make_secure_val(val):
        return val


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
        # for rendering basic templates

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


# Blog functions

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class BlogFront(Handler):
    def get(self):
        posts = Post.all().order('-created')
        self.render('front.html', posts=posts, user=self.user)

    def post(self):
        posts = Post.all().order('-created')
        if(self.request.get('like')):
            likedpost = self.request.get('like')
            key = db.Key.from_path('Post', int(likedpost), parent=blog_key())
            post = db.get(key)
            likes = post.likes
            likers = post.likers
            error = ""
            if self.user:
                if post.author == self.user.name:
                    error = "The author of a post cannot like their own post"
                elif self.user.name in post.likers:
                    post.likes -= 1
                    post.likers.remove(self.user.name)
                    post.put()
                else:
                    post.likes = post.likes + 1
                    post.likers.append(self.user.name)
                    post.put()
            else:
                self.redirect("/login")
        time.sleep(0.2)
        self.render('front.html', posts=posts, user=self.user, error=error)


class PostPage(Handler):
    '''
        Renders the permalink page for each blog post
    '''
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        likes = post.likes
        likers = post.likers

        comments = db.GqlQuery("select * from Comment where post_id = " +
                               post_id + " order by created desc")

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post, user=self.user,
                    comments=comments)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        likes = post.likes
        likers = post.likers
        error = ""

        if(self.user):
            if(self.request.get('like') == post_id):
                if post.author == self.user.name:
                    error = "The author of a post cannot like their own post"
                elif self.user.name in post.likers:
                    post.likes -= 1
                    post.likers.remove(self.user.name)
                    post.put()
                else:
                    post.likes = post.likes + 1
                    post.likers.append(self.user.name)
                    post.put()

            if(self.request.get('comment')):
                c = Comment(parent=blog_key(),
                            content=self.request.get('comment'),
                            post_id=int(post_id), user_id=self.user.key().id())
                post.comment_count = post.comment_count + 1
                post.put()
                c.put()

            comments = db.GqlQuery("select * from Comment where post_id = " +
                                   post_id + " order by created desc")

            time.sleep(0.2)

            self.render("permalink.html", post=post, user=self.user,
                        error=error, comments=comments)
        else:
            self.redirect("/login")


class NewPost(Handler):
    def get(self):
        if self.user:
            self.render("newpost.html", user=self.user)
        else:
            # if there is no self.user (aka, not logged in) then it redirects
            self.redirect("/login")

    def post(self):
        if not self.user:
            # cannot post if not logged in
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if (self.request.get('submit') == 'change'):
            if subject and content:
                p = Post(parent=blog_key(), subject=subject,
                         content=content, author=self.user.name,
                         likes=0, likers=[], comment_count=0)
                p.put()
                self.redirect('/blog/%s' % str(p.key().id()))
            else:
                error = "Each post must include a subject and content"
                self.render("newpost.html", subject=subject, content=content,
                            error=error)
        else:
            self.redirect('/blog')


class EditPost(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        comments = db.GqlQuery("select * from Comment where post_id = " +
                               post_id + " order by created desc")

        if not self.user:
            self.redirect('/login')
        elif self.user.name == post.author:
            self.render("newpost.html", subject=post.subject,
                        content=post.content)
        else:
            msg = "Only the post's author can edit the post"
            self.render("permalink.html", post=post, user=self.user, error=msg,
                        comments=comments)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not self.user:
            # cannot post if not logged in
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if (self.request.get('submit') == 'change'):
            if self.user.name == post.author:
                if subject and content:
                    post.subject = subject
                    post.content = content
                    post.put()
                    self.redirect('/blog/%s' % str(post.key().id()))
                else:
                    error = "Each post must include a subject and content"
                    self.render("newpost.html", subject=subject,
                                content=content, error=error)
            else:
                error = "Only the post's author can edit the post."
                self.render("newpost.html", subject-subject, content=content,
                            error=error)
        else:
            self.redirect('/blog/%s' % str(post.key().id()))


class DeletePost(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not self.user:
            self.redirect('/login')
        elif self.user.name == post.author:
            self.render("permalink.html", post=post, user=self.user,
                        delete=True)
        else:
            msg = "Only the post's author can delete the post"
            self.render("permalink.html", post=post, user=self.user, error=msg)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if (self.request.get("delete")):
            if self.user.name == post.author:
                post.delete()
                time.sleep(0.2)
                self.redirect('/blog')
            else:
                msg = "Only the post's author can delete the post"
                self.render("permalink.html", post=post, user=self.user,
                            error=msg)
        else:
            self.redirect('/blog')


class EditComment(Handler):
    def get(self, post_id, comment_id):
        postkey = db.Key.from_path('Post', int(post_id), parent=blog_key())
        key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
        post = db.get(postkey)
        comment = db.get(key)

        comments = db.GqlQuery("select * from Comment where post_id = " +
                               post_id + " order by created desc")

        if not self.user:
            self.redirect('/login')
        elif self.user.name == comment.getUserName():
            self.render("editcomment.html", content=comment.content,
                        user=self.user)
        else:
            msg = "Only the comment's author can edit a commment"
            self.render("permalink.html", post=post, user=self.user,
                        error=msg, comments=comments)

    def post(self, post_id, comment_id):
        key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
        comment = db.get(key)

        comments = db.GqlQuery("select * from Comment where post_id = " +
                               post_id + " order by created desc")

        if not self.user:
            # cannot post if not logged in
            self.redirect('/blog')

        content = self.request.get('content')

        if (self.request.get('submit') == 'change'):
            if self.user.name == comment.getUserName():
                if content:
                    comment.content = content
                    comment.put()
                    self.redirect('/blog/%s' % post_id)
                else:
                    error = "Each comment must include content"
                    self.render("editcomment.html", content=content,
                                error=error)
            else:
                msg = "Only the comment's author can edit a commment"
                self.render("permalink.html", post=post, user=self.user,
                            error=msg, comments=comments)
        else:
            self.redirect('/blog/%s' % post_id)


class DeleteComment(Handler):
    def get(self, post_id, comment_id):
        postkey = db.Key.from_path('Post', int(post_id), parent=blog_key())
        key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
        post = db.get(postkey)
        comment = db.get(key)

        comments = db.GqlQuery("select * from Comment where post_id = " +
                               post_id + " order by created desc")

        if not self.user:
            self.redirect('/login')
        elif self.user.name == comment.getUserName():
            self.render("editcomment.html", content=comment.content,
                        user=self.user, delete=True)
        else:
            msg = "Only the comment's author can delete the comment"
            self.render("permalink.html", post=post, user=self.user, error=msg,
                        comments=comments)

    def post(self, post_id, comment_id):
        postkey = db.Key.from_path('Post', int(post_id), parent=blog_key())
        key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
        post = db.get(postkey)
        comment = db.get(key)

        comments = db.GqlQuery("select * from Comment where post_id = " +
                               post_id + " order by created desc")

        if (self.request.get("delete")):
            if self.user.name == comment.getUserName():
                comment.delete()
                post.comment_count -= 1
                post.put()
                time.sleep(0.2)
                self.redirect('/blog/%s' % post_id)
            else:
                msg = "Only the comment's author can delete the comment"
                self.render("permalink.html", post=post, user=self.user,
                            error=msg, comments=comments)
        else:
            self.redirect('/blog/%s' % post_id)


class MainPage(Handler):
    def get(self):
        self.redirect("/blog")


class SignUp(Handler):
    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        # We are going to get all the data from the form
        self.username = self.request.get("username")
        self.password = self.request.get("password")
        self.password2 = self.request.get("password2")
        self.email = self.request.get("email")

        params = dict(username=self.username, email=self.email)

        # then check the data to see if correct
        # if something is wrong, pass along error message
        # when we re-render the signup page

        if not checkUsername(self.username):
            params['username_error'] = "That is not a valid username."
            have_error = True

        if not checkPassword(self.password):
            params['password_error'] = "That is not a valid password."
            have_error = True
        elif self.password != self.password2:
            params['password_mismatch'] = "Your passwords do not match."
            have_error = True

        if not checkEmail(self.email):
            params['email_error'] = "That is not a valid email address."

        # If everything is correct, then pass the username over to the
        # hello.html page.
        if have_error:
            self.render("signup.html", **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(SignUp):
    # extends the SignUp class
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        # username comes from the SignuUp class
        # checks to see if there is a User object with that name
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', username_error=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            # this creates a user object
            u.put()
            # and stores it in the database

            self.login(u)
            self.redirect('/blog')


class Login(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            # It would be neat to change this to say if its a wrong pw
            # or if the username does not exist
            msg = 'Invalid login'
            self.render('login.html', error=msg)


class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/blog')


class Welcome(Handler):
    def get(self):
        username = self.request.get('username')
        if checkUsername(username):
            self.render('hello.html', username=username)
        else:
            self.redirect('/signup')

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/signup', Register),
                               ('/hello', Welcome),
                               ('/blog/?', BlogFront),
                               ('/login', Login),
                               ('/blog/newpost', NewPost),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/edit/([0-9]+)', EditPost),
                               ('/blog/delete/([0-9]+)', DeletePost),
                               ('/blog/edit/([0-9]+)/([0-9]+)', EditComment),
                               ('/blog/delete/([0-9]+)/([0-9]+)',
                                DeleteComment),
                               ('/logout', Logout)], debug=True)
