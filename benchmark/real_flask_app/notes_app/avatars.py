import os

from PIL import Image
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
AVATAR_SIZE = (128, 128)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def save_avatar(upload, folder, username):
    """Store a square thumbnail of the uploaded image as <username>.png."""
    safe_name = secure_filename(username) or "user"
    img = Image.open(upload.stream)
    img = img.convert("RGB")
    img.thumbnail(AVATAR_SIZE)
    target = os.path.join(folder, f"{safe_name}.png")
    img.save(target, format="PNG")
    return target
