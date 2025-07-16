from flask import Flask, request, render_template, redirect, url_for, flash, session
from functools import wraps
import firebase_admin
from firebase_admin import credentials, firestore
from datetime import datetime
import json
import os
import hashlib
import time
from uuid import uuid4
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-here')

# Create upload directory if it doesn't exist
upload_dir = 'static/uploads'
if not os.path.exists(upload_dir):
    os.makedirs(upload_dir)

def require_login(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login to access this page.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Load Firebase config from environment variable or local file
firebase_config_str = os.environ.get("FIREBASE_CONFIG_JSON")

if firebase_config_str is None:
    # For local development, load from firebase_config.json file
    try:
        with open('firebase_config.json', 'r') as f:
            config_dict = json.load(f)
        print("✅ Loaded Firebase config from local file")
    except FileNotFoundError:
        raise ValueError("Firebase config not found. Either set FIREBASE_CONFIG_JSON environment variable or place firebase_config.json in the project directory.")
else:
    # For production (Render), load from environment variable
    config_dict = json.loads(firebase_config_str)
    config_dict["private_key"] = config_dict["private_key"].replace("\\n", "\n")
    print("✅ Loaded Firebase config from environment variable")

cred = credentials.Certificate(config_dict)
firebase_admin.initialize_app(cred)
db = firestore.client()

blogs_collection = "blogs"
users_collection = "users"
comments_collection = "comments"

# Admin email - change this to your admin email
ADMIN_EMAIL = "dattu@gmail.com"

def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def login_required(f):
    """Decorator to require login for certain routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin access"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))

        try:
            user_doc = db.collection(users_collection).document(session['user_id']).get()
            if not user_doc.exists or user_doc.to_dict().get('email') != ADMIN_EMAIL:
                flash('Admin access required.', 'error')
                return redirect(url_for('login'))
        except Exception as e:
            print('An error occurred:', e)
            flash('Error verifying admin access.', 'error')
            return redirect(url_for('login'))

        return f(*args, **kwargs)
    return decorated_function

def safe_query_execution(query_func, fallback_data=None):
    try:
        return query_func()
    except Exception as e:
        print(f"Firestore query error: {e}")
        if "index" in str(e).lower():
            print("Index creation required. Check Firebase console for index creation links.")
        return fallback_data or []

def process_post_doc(doc):
    """Helper function to process Firestore document into post dict"""
    post_data = doc.to_dict()
    return {
        'id': doc.id,
        'int_id': post_data.get('int_id', 0),
        'title': post_data.get('title', 'Untitled'),
        'content': post_data.get('content', ''),
        'author': post_data.get('author', 'Anonymous'),
        'user_id': post_data.get('user_id', ''),
        'timestamp': post_data.get('timestamp', datetime.now()),
        'image': post_data.get('image', None),
        'likes': post_data.get('likes', 0)
    }

# Homepage — view public posts or user's own posts
@app.route('/')
@login_required
def index():
    try:
        posts_ref = db.collection(blogs_collection).order_by("timestamp", direction=firestore.Query.DESCENDING)
        docs = posts_ref.stream()
        posts = [process_post_doc(doc) for doc in docs]
    except Exception as e:
        print(f"Error in index route: {e}")
        posts = []
    
    if session.get("email") == ADMIN_EMAIL:
        return render_template("index_admin.html", posts=posts)
    else:
        return render_template("index_user.html", posts=posts)

# Register page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Validation
        if not username or not email or not password:
            flash('All fields are required.', 'error')
            return render_template('register.html')

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')

        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('register.html')

        try:
            # Check if email already exists
            users_ref = db.collection(users_collection).where("email", "==", email).limit(1).stream()
            if any(users_ref):
                flash('Email already registered. Please login instead.', 'error')
                return render_template('register.html')

            # Create new user
            user_data = {
                'username': username,
                'email': email,
                'password': hash_password(password),
                'created_at': datetime.now()
            }

            user_ref = db.collection(users_collection).add(user_data)
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            print(f"Registration error: {e}")
            flash('Registration failed. Please try again.', 'error')
            return render_template('register.html')
    
    return render_template('register.html')

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']

        if not email or not password:
            flash('Email and password are required.', 'error')
            return render_template('login.html')

        try:
            # Find user by email
            users_ref = db.collection(users_collection).where("email", "==", email).limit(1).stream()
            user_doc = None
            user_id = None

            for doc in users_ref:
                user_doc = doc.to_dict()
                user_id = doc.id
                break

            if not user_doc:
                flash('Invalid email or password.', 'error')
                return render_template('login.html')

            # Check password
            if user_doc['password'] != hash_password(password):
                flash('Invalid email or password.', 'error')
                return render_template('login.html')

            # Login successful
            session['user_id'] = user_id
            session['username'] = user_doc['username']
            session['email'] = user_doc['email']
            flash(f'Welcome back, {user_doc["username"]}!', 'success')
            return redirect(url_for('index'))

        except Exception as e:
            print(f"Login error: {e}")
            flash('Login failed. Please try again.', 'error')
            return render_template('login.html')
    
    return render_template('login.html')

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

# Blog submission form (requires login)
@app.route('/blog', methods=['GET', 'POST'])
@login_required
def blog():
    if request.method == 'POST':
        title = request.form['title']
        content_text = request.form['content']
        image_url = None
        image = request.files.get('image')

        if image and image.filename:
            filename = f"{uuid4().hex}_" + secure_filename(image.filename)
            image.save(os.path.join('static/uploads', filename))
            image_url = url_for('static', filename='uploads/' + filename)

        try:
            counter_ref = db.collection('settings').document('counters')
            counter_doc = counter_ref.get()
            last_id = counter_doc.to_dict().get('last_post_id', 100) if counter_doc.exists else 100
            next_id = last_id + 1
            counter_ref.set({'last_post_id': next_id}, merge=True)
        except Exception as e:
            print("Error reading post counter:", e)
            next_id = int(time.time())  # fallback

        blog_data = {
            'int_id': next_id,
            'title': title,
            'content': content_text,
            'author': session['username'],
            'user_id': session['user_id'],
            'timestamp': datetime.now(),
            'image': image_url,
            'likes': 0
        }

        try:
            db.collection(blogs_collection).add(blog_data)
            flash("Post published successfully!", "success")
            return redirect(url_for('index'))
        except Exception as e:
            print(f"Error publishing post: {e}")
            flash("Failed to publish post. Please try again.", "error")

    return render_template('blog.html')

@app.route('/delete-my-post/<int:int_id>', methods=['POST'])
@login_required
def delete_my_post(int_id):
    try:
        docs = db.collection(blogs_collection).where('int_id', '==', int_id).limit(1).stream()
        doc = next(docs, None)

        if not doc or not doc.exists:
            flash("Post not found.", "error")
            return redirect(url_for('index'))

        post = doc.to_dict()
        is_admin = session.get('email') == ADMIN_EMAIL
        is_owner = session.get('user_id') == post.get('user_id')

        if is_admin or is_owner:
            db.collection(blogs_collection).document(doc.id).delete()
            flash("Post deleted successfully.", "success")
        else:
            flash("You can't delete others posts.", "error")
    except Exception as e:
        print(f"Error deleting post: {e}")
        flash("Failed to delete post.", "error")
    
    return redirect(url_for('index'))
@app.route("/delete/<id>", methods=["POST"])
@admin_required
def delete_admin(id):
    try:
        db.collection(blogs_collection).document(id).delete()
        flash("Post deleted by admin.", "success")
    except Exception as e:
        print(f"Error deleting post by admin: {e}")
        flash("Failed to delete post.", "error")
    return redirect(url_for("index"))

@app.route('/like/<int:int_id>', methods=['POST'])
@login_required
def like_post(int_id):
    try:
        post_docs = db.collection(blogs_collection).where('int_id', '==', int_id).limit(1).stream()
        post_doc = next(post_docs, None)

        if post_doc:
            doc_ref = db.collection(blogs_collection).document(post_doc.id)
            post_data = post_doc.to_dict()
            current_likes = post_data.get("likes", 0)
            doc_ref.update({"likes": current_likes + 1})
            flash("Post liked!", "success")
        else:
            flash("Post not found.", "error")
    except Exception as e:
        print(f"Error liking post: {e}")
        flash("Failed to like post.", "error")
    
    return redirect(url_for('index'))

@app.route('/post/<int:int_id>')
@login_required
def view_post(int_id):
    try:
        post_docs = db.collection(blogs_collection).where('int_id', '==', int_id).limit(1).stream()
        post_doc = next(post_docs, None)

        if not post_doc:
            flash("Post not found.", "error")
            return redirect(url_for('index'))

        post = post_doc.to_dict()
        post["int_id"] = int_id
        post["id"] = post_doc.id

        comment_docs = db.collection(blogs_collection).document(post_doc.id).collection('comments').order_by('timestamp').stream()
        comments = [c.to_dict() for c in comment_docs]

        return render_template("post_detail.html", post=post, comments=comments)
    except Exception as e:
        print(f"Error viewing post: {e}")
        flash("Failed to load post.", "error")
        return redirect(url_for('index'))


@app.route("/my-posts")
@require_login
def myposts():
    user_id = session.get("user_id")
    if not user_id:
        flash("Login required to view your posts", "warning")
        return redirect(url_for('login'))

    try:
        posts_ref = db.collection(blogs_collection).where('user_id', '==', user_id).order_by("timestamp", direction=firestore.Query.DESCENDING)
        docs = posts_ref.stream()
        user_posts = [process_post_doc(doc) for doc in docs]
    except Exception as e:
        print(f"Error loading user posts: {e}")
        user_posts = []
        flash("Failed to load your posts.", "error")

    return render_template("myposts.html", posts=user_posts)

@app.route("/edit/<int:int_id>", methods=["GET", "POST"])
@require_login
def edit_post(int_id):
    try:
        post_docs = db.collection(blogs_collection).where('int_id', '==', int_id).limit(1).stream()
        post_doc = next(post_docs, None)
        
        if not post_doc:
            flash("Post not found.", "error")
            return redirect(url_for('index'))
        
        post_data = post_doc.to_dict()
        
        # Authorization check
        if post_data.get("user_id") != session.get("user_id") and session.get("email") != ADMIN_EMAIL:
            flash("You are not authorized to edit this post.", "error")
            return redirect(url_for('index'))

        if request.method == "POST":
            title = request.form.get("title")
            content = request.form.get("content")
            image_file = request.files.get("image")

            updated_data = {
                "title": title,
                "content": content,
            }

            if image_file and image_file.filename:
                filename = f"{uuid4().hex}_" + secure_filename(image_file.filename)
                image_path = os.path.join('static/uploads', filename)
                image_file.save(image_path)
                updated_data["image"] = url_for('static', filename='uploads/' + filename)

            try:
                db.collection(blogs_collection).document(post_doc.id).update(updated_data)
                flash("Post updated successfully!", "success")
                return redirect(url_for('view_post', int_id=int_id))
            except Exception as e:
                print(f"Error updating post: {e}")
                flash("Failed to update post.", "error")

        return render_template("edit_post.html", post=post_data, int_id=int_id)
    
    except Exception as e:
        print(f"Error in edit_post: {e}")
        flash("Error loading post for editing.", "error")
        return redirect(url_for('index'))
@app.route("/comment/<id>", methods=["POST"])
@login_required
def comment_post(id):
    user = session.get("username")
    text = request.form.get("comment")
    int_id = request.form.get("int_id")

    try:
        comment = {
            "user": user,
            "text": text,
            "timestamp": datetime.now()
        }
        db.collection(blogs_collection).document(id).collection('comments').add(comment)
        flash("Comment added!", "success")
    except Exception as e:
        print(f"Error posting comment: {e}")
        flash("Failed to comment.", "error")

    return redirect(url_for("view_post", int_id=int(int_id)))

@app.route("/admin")
@admin_required
def admin_panel():
    try:
        posts_ref = db.collection(blogs_collection).order_by("timestamp", direction=firestore.Query.DESCENDING)
        post_docs = posts_ref.stream()
        posts = [process_post_doc(doc) for doc in post_docs]

        user_docs = db.collection(users_collection).stream()
        users = []
        for doc in user_docs:
            data = doc.to_dict()
            data['id'] = doc.id
            users.append(data)

        return render_template("admin.html", posts=posts, users=users)
    except Exception as e:
        print(f"Admin panel error: {e}")
        flash("Failed to load admin panel.", "error")
        return redirect(url_for("index"))


@app.route("/delete-user/<user_id>", methods=["POST"])
@admin_required
def delete_user_account(user_id):
    try:
        # Delete user document
        db.collection(users_collection).document(user_id).delete()
        flash("User account deleted.", "success")

        # Fetch and delete all posts by this user
        user_posts = db.collection(blogs_collection).where("user_id", "==", user_id).stream()
        for post_doc in user_posts:
            post_id = post_doc.id
            # Delete comments subcollection first if it exists
            comments_ref = db.collection(blogs_collection).document(post_id).collection('comments')
            comments = comments_ref.stream()
            for comment in comments:
                comments_ref.document(comment.id).delete()
            # Then delete the post itself
            db.collection(blogs_collection).document(post_id).delete()

        flash("All posts by this user have been deleted.", "info")
    except Exception as e:
        print(f"Error deleting user and their posts: {e}")
        flash("An error occurred while deleting user and their posts.", "error")

    return redirect(url_for("index"))



if __name__ == '__main__':
    app.run(debug=True)