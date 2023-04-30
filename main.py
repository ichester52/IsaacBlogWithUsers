from flask import Flask, render_template, redirect, url_for, flash
from sqlalchemy import Table, Column, Integer, ForeignKey
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterUser, LoginForm, CommentForm
from functools import wraps
from flask_gravatar import Gravatar

def admin_only(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.get_id():
            if current_user.get_id() == "1":
                return func(*args, **kwargs)
                print("this is being hit")
            else:
                return "<h1>Forbidden</h1>" \
                       "<p> you do not have access to this page </p>"
        else:
            return "<h1>Forbidden</h1>" \
                   "<p> you do not have access to this page </p>"
    return wrapper



app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

    posts = relationship("BlogPost", back_populates='author')
    comments = relationship("Comments")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comments")
# db.create_all()

class Comments(db.Model):
    __tablename__ = "comments"
    commentor_id = db.Column(db.Integer, ForeignKey("users.id"))
    #come back to this because you did not set a back_populates
    commentor = relationship("User")
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text, nullable=False)
    blog_id = db.Column(db.Integer, ForeignKey("blog_posts.id"))
    post = relationship("BlogPost")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def get_all_posts():
    user_id = current_user.get_id()
    print(type(user_id))
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, user_id=user_id)


@app.route('/register', methods=["POST", "GET"])
def register():
    form = RegisterUser()
    if form.validate_on_submit():
        new_user = User(email=form.email.data, password = generate_password_hash(form.password.data, method="pbkdf2:sha256", salt_length=8), name=form.name.data)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)

        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form)


@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user:
            access_granted = check_password_hash(user.password, form.password.data)
            if access_granted:
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash("sorry this is the wrong password")
        else:
            flash("sorry this user does not exist")
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))

@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    post_comments = Comments.query.filter_by(blog_id=post_id)
    if form.validate_on_submit():
        comment = Comments(
            commentor_id=current_user.id,
            body=form.body.data,
            blog_id=post_id
        )

        db.session.add(comment)
        db.session.commit()

        return redirect(url_for('get_all_posts'))
    requested_post = BlogPost.query.get(post_id)
    return render_template("post.html", post=requested_post, form=form, comments=post_comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    user = User.query.filter_by(id=int(current_user.get_id())).first()
    form = CreatePostForm()
    print(current_user.id)
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)

@app.route("/edit-post/<int:post_id>", methods=["POST", "GET"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)

@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
