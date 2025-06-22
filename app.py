from flask import Flask, request, render_template, redirect
import firebase_admin
from firebase_admin import credentials, firestore
from datetime import datetime
import json
import os

app = Flask(__name__)

# ✅ Load Firebase config from environment variable
firebase_config_str = os.environ.get("FIREBASE_CONFIG_JSON")
if firebase_config_str is None:
    raise ValueError("FIREBASE_CONFIG_JSON environment variable is not set.")

firebase_config = json.loads(firebase_config_str)
cred = credentials.Certificate(firebase_config)
firebase_admin.initialize_app(cred)
db = firestore.client()

collection_name = "blogs"

# 🏠 Homepage — view posts
@app.route('/')
def index():
    posts_ref = db.collection(collection_name).order_by("timestamp", direction=firestore.Query.DESCENDING)
    docs = posts_ref.stream()
    posts = [{'id': doc.id,
              'title': doc.to_dict().get('title'),
              'content': doc.to_dict().get('content'),
              'author': doc.to_dict().get('author')} for doc in docs]
    return render_template('index.html', posts=posts)

# ✍️ Blog submission form
@app.route('/blog', methods=['GET', 'POST'])
def blog():
    if request.method == 'POST':
        author = request.form['author']
        title = request.form['title']
        content = request.form['content']
        db.collection(collection_name).add({
            'author': author,
            'title': title,
            'content': content,
            'timestamp': datetime.now()
        })
        return redirect('/admin')
    return render_template('blog.html')

# 👩‍💻 Admin panel — view & delete
@app.route('/admin')
def admin():
    posts_ref = db.collection(collection_name).order_by("timestamp", direction=firestore.Query.DESCENDING)
    docs = posts_ref.stream()
    posts = [{'id': doc.id,
              'title': doc.to_dict().get('title'),
              'content': doc.to_dict().get('content'),
              'author': doc.to_dict().get('author')} for doc in docs]
    return render_template('admin.html', posts=posts)

# ❌ Delete post
@app.route('/delete/<post_id>', methods=['POST'])
def delete_post(post_id):
    db.collection(collection_name).document(post_id).delete()
    return redirect('/admin')

# 🔁 Local testing only
if __name__ == '__main__':
    app.run(debug=True)
