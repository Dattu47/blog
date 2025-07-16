import firebase_admin
from firebase_admin import credentials, firestore, storage
import uuid
import datetime
from werkzeug.utils import secure_filename

cred = credentials.Certificate("firebase_config.json")
firebase_admin.initialize_app(cred, {
    'storageBucket': 'blogapp-9d501.appspot.com'
})

db = firestore.client()
bucket = storage.bucket()

def upload_image(file):
    if not file:
        return None
    filename = secure_filename(file.filename)
    blob = bucket.blob(f"blog_images/{uuid.uuid4().hex}_{filename}")
    blob.upload_from_file(file.stream, content_type=file.content_type)
    blob.make_public()
    return blob.public_url

def save_blog(title, content, author, email, image_url=None):
    blog_data = {
        'title': title,
        'content': content,
        'author': author,
        'email': email,
        'timestamp': datetime.datetime.utcnow(),
        'image': image_url
    }
    db.collection("blogs").add(blog_data)

def get_blogs():
    blogs = []
    docs = db.collection("blogs").order_by("timestamp", direction=firestore.Query.DESCENDING).stream()
    for doc in docs:
        blog = doc.to_dict()
        blog['id'] = doc.id
        blog['timestamp'] = blog['timestamp'].replace(tzinfo=None)
        blogs.append(blog)
    return blogs

def get_blog(blog_id):
    doc = db.collection("blogs").document(blog_id).get()
    if doc.exists:
        data = doc.to_dict()
        data['id'] = doc.id
        data['timestamp'] = data['timestamp'].replace(tzinfo=None)
        return data
    return None

def delete_blog(blog_id):
    db.collection("blogs").document(blog_id).delete()

def update_blog(blog_id, data):
    db.collection("blogs").document(blog_id).update(data)

def add_comment(blog_id, user, text):
    comment_data = {
        'user': user,
        'text': text,
        'timestamp': datetime.datetime.utcnow()
    }
    db.collection("blogs").document(blog_id).collection("comments").add(comment_data)

def get_comments(blog_id):
    comments = []
    docs = db.collection("blogs").document(blog_id).collection("comments").order_by("timestamp").stream()
    for doc in docs:
        comment = doc.to_dict()
        comment['timestamp'] = comment['timestamp'].replace(tzinfo=None)
        comments.append(comment)
    return comments
