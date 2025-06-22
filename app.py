from flask import Flask, request, render_template, redirect, url_for, flash, session
import firebase_admin
from firebase_admin import credentials, firestore
from datetime import datetime
import json
import os
import hashlib
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-here')  # Change this in production

# ✅ Load Firebase config from environment variable or local file
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

# Admin email - change this to your admin email
ADMIN_EMAIL = "admin@blogapp.com"  # Change this to your actual admin email

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
                return redirect(url_for('index'))
        except Exception as e:
            print(f"Error checking admin status: {e}")
            flash('Error verifying admin access.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def safe_query_execution(query_func, fallback_data=None):
    """Safely execute Firestore queries with fallback"""
    try:
        return query_func()
    except Exception as e:
        print(f"Firestore query error: {e}")
        if "index" in str(e).lower():
            print("Index creation required. Check Firebase console for index creation links.")
        return fallback_data or []

# 🏠 Homepage — view public posts or user's own posts
@app.route('/')
def index():
    posts = []
    
    if 'user_id' in session:
        try:
            # Check if user is admin
            user_doc = db.collection(users_collection).document(session['user_id']).get()
            is_admin = user_doc.exists and user_doc.to_dict().get('email') == ADMIN_EMAIL
            
            if is_admin:
                # Admin sees all posts
                def get_admin_posts():
                    posts_ref = db.collection(blogs_collection).order_by("timestamp", direction=firestore.Query.DESCENDING)
                    docs = posts_ref.stream()
                    return [process_post_doc(doc) for doc in docs]
                
                posts = safe_query_execution(get_admin_posts)
            else:
                # Regular user sees only their posts - using simpler query approach
                def get_user_posts():
                    # First get all user posts, then sort in Python to avoid index issues
                    posts_ref = db.collection(blogs_collection).where("user_id", "==", session['user_id'])
                    docs = posts_ref.stream()
                    user_posts = [process_post_doc(doc) for doc in docs]
                    # Sort by timestamp in Python
                    return sorted(user_posts, key=lambda x: x.get('timestamp', datetime.min), reverse=True)
                
                posts = safe_query_execution(get_user_posts)
        except Exception as e:
            print(f"Error in index route: {e}")
            flash('Error loading posts. Please try again.', 'error')
    else:
        # Not logged in, show recent public posts
        def get_public_posts():
            posts_ref = db.collection(blogs_collection).order_by("timestamp", direction=firestore.Query.DESCENDING).limit(5)
            docs = posts_ref.stream()
            return [process_post_doc(doc) for doc in docs]
        
        posts = safe_query_execution(get_public_posts)
    
    return render_template('index.html', posts=posts)

def process_post_doc(doc):
    """Helper function to process Firestore document into post dict"""
    post_data = doc.to_dict()
    return {
        'id': doc.id,
        'title': post_data.get('title', 'Untitled'),
        'content': post_data.get('content', ''),
        'author': post_data.get('author', 'Anonymous'),
        'timestamp': post_data.get('timestamp', datetime.now())
    }

# 📝 Register page
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

# 🔐 Login page
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

# 🚪 Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('index'))

# ✍️ Blog submission form (requires login)
@app.route('/blog', methods=['GET', 'POST'])
@login_required
def blog():
    if request.method == 'POST':
        title = request.form['title'].strip()
        content = request.form['content'].strip()
        
        if not title or not content:
            flash('Title and content are required.', 'error')
            return render_template('blog.html')
        
        try:
            blog_data = {
                'author': session['username'],
                'title': title,
                'content': content,
                'user_id': session['user_id'],
                'timestamp': datetime.now()
            }
            
            db.collection(blogs_collection).add(blog_data)
            flash('Blog post published successfully!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            print(f"Blog creation error: {e}")
            flash('Failed to publish blog post. Please try again.', 'error')
            return render_template('blog.html')
    
    return render_template('blog.html')

# 👩‍💻 Admin panel — view & delete (admin only)
@app.route('/admin')
@admin_required
def admin():
    def get_all_posts():
        posts_ref = db.collection(blogs_collection).order_by("timestamp", direction=firestore.Query.DESCENDING)
        docs = posts_ref.stream()
        return [process_post_doc(doc) for doc in docs]
    
    posts = safe_query_execution(get_all_posts)
    return render_template('admin.html', posts=posts)

# ❌ Delete post (admin only)
@app.route('/delete/<post_id>', methods=['POST'])
@admin_required
def delete_post(post_id):
    try:
        db.collection(blogs_collection).document(post_id).delete()
        flash('Blog post deleted successfully.', 'success')
    except Exception as e:
        print(f"Delete error: {e}")
        flash('Failed to delete blog post.', 'error')
    return redirect(url_for('admin'))

# 📊 My Posts - user's own posts
@app.route('/my-posts')
@login_required
def myposts():
    def get_my_posts():
        # Get user posts without ordering in Firestore to avoid index issues
        posts_ref = db.collection(blogs_collection).where("user_id", "==", session['user_id'])
        docs = posts_ref.stream()
        user_posts = [process_post_doc(doc) for doc in docs]
        # Sort by timestamp in Python
        return sorted(user_posts, key=lambda x: x.get('timestamp', datetime.min), reverse=True)
    
    posts = safe_query_execution(get_my_posts)
    return render_template('myposts.html', posts=posts)

# ❌ Delete own post
@app.route('/delete-my-post/<post_id>', methods=['POST'])
@login_required
def delete_my_post(post_id):
    try:
        # Verify the post belongs to the current user
        post_doc = db.collection(blogs_collection).document(post_id).get()
        if post_doc.exists and post_doc.to_dict().get('user_id') == session['user_id']:
            db.collection(blogs_collection).document(post_id).delete()
            flash('Your blog post has been deleted.', 'success')
        else:
            flash('You can only delete your own posts.', 'error')
    except Exception as e:
        print(f"Delete my post error: {e}")
        flash('Failed to delete your post.', 'error')
    
    return redirect(url_for('myposts'))

# 🔁 Local testing only
if __name__ == '__main__':
    app.run(debug=True)