from flask import Flask, request, redirect, url_for, render_template, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from cryptography.fernet import Fernet, InvalidToken
import csv
import io
import base64
from werkzeug.utils import secure_filename
import os
import zipfile
import shutil
from datetime import datetime
import logging
import tempfile

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///passwords.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'
db = SQLAlchemy(app)
migrate = Migrate(app, db)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Hàm đọc key và mật khẩu từ file config.txt
def load_config():
    try:
        with open('config.txt', 'r') as f:
            lines = f.readlines()
            config = {}
            for line in lines:
                key, value = line.strip().split('=', 1)
                config[key] = value
            if 'ENCRYPTION_KEY' not in config or 'LOGIN_PASSWORD' not in config:
                raise ValueError("Missing ENCRYPTION_KEY or LOGIN_PASSWORD in config.txt")
            return config['ENCRYPTION_KEY'], config['LOGIN_PASSWORD']
    except (FileNotFoundError, ValueError):
        # Nếu file không tồn tại hoặc lỗi định dạng, tạo file với giá trị mặc định
        with open('config.txt', 'w') as f:
            f.write('ENCRYPTION_KEY=2312\nLOGIN_PASSWORD=2312\n')
        return '2312', '2312'


# Khởi tạo cipher
def get_cipher(key):
    try:
        key_bytes = key.encode().ljust(32, b'0')  # Fernet yêu cầu key 32 bytes
        return Fernet(base64.urlsafe_b64encode(key_bytes))
    except Exception as e:
        print(f"Error initializing cipher: {e}")
        return None


# Đọc key và mật khẩu từ file
ENCRYPTION_KEY, LOGIN_PASSWORD = load_config()
cipher = get_cipher(ENCRYPTION_KEY)
if cipher is None:
    raise RuntimeError("Failed to initialize encryption cipher")


# Filter tùy chỉnh để giải mã mật khẩu trong template
@app.template_filter('decrypt')
def decrypt_filter(encrypted_text):
    if not cipher:
        return "Error: Cipher not initialized"
    try:
        return cipher.decrypt(encrypted_text.encode()).decode()
    except InvalidToken:
        return "Error: Invalid key"
    except Exception:
        return "Error: Decryption failed"


class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    url = db.Column(db.String(200))
    username = db.Column(db.String(100))
    password = db.Column(db.String(200))
    otpauth = db.Column(db.String(200))
    notes = db.Column(db.Text)
    images = db.relationship('Image', backref='password', lazy=True)


class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.LargeBinary, nullable=False)
    filename = db.Column(db.String(100), nullable=False)
    mimetype = db.Column(db.String(50), nullable=False)
    password_id = db.Column(db.Integer, db.ForeignKey('password.id'), nullable=False)


@app.route('/')
def index():
    if 'authenticated' not in session:
        return redirect(url_for('login'))

    # Get sorting parameters from query
    sort_by = request.args.get('sort_by', 'title')
    sort_order = request.args.get('sort_order', 'asc')

    # Validate sort_by to prevent SQL injection
    valid_columns = ['title', 'username', 'url', 'notes']  # Thêm 'notes'
    if sort_by not in valid_columns:
        sort_by = 'title'

    # Determine sort column and order
    sort_column = getattr(Password, sort_by)
    if sort_order == 'desc':
        sort_column = sort_column.desc()
    else:
        sort_order = 'asc'  # Default to asc if invalid

    # Query passwords with sorting
    passwords = Password.query.order_by(sort_column).all()

    return render_template('index.html', passwords=passwords, sort_by=sort_by, sort_order=sort_order)


@app.route('/import_csv', methods=['POST'])
def import_csv():
    if 'authenticated' not in session:
        return redirect(url_for('login'))
    if 'file' not in request.files:
        flash('No file part')
        return redirect(url_for('index', sort_by=request.form.get('sort_by', 'title'),
                                sort_order=request.form.get('sort_order', 'asc')))
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('index', sort_by=request.form.get('sort_by', 'title'),
                                sort_order=request.form.get('sort_order', 'asc')))
    if file:
        stream = io.StringIO(file.stream.read().decode("UTF-8"), newline=None)
        csv_reader = csv.DictReader(stream)
        imported_count = 0
        skipped_count = 0
        for row in csv_reader:
            # Chuẩn hóa dữ liệu từ CSV
            title = row['Title'].strip() if row['Title'] else ''
            url = row['URL'].strip() if row['URL'] else ''
            username = row['Username'].strip() if row['Username'] else ''
            password = row['Password'].strip() if row['Password'] else ''
            notes = row['Notes'].strip() if row['Notes'] else ''
            otpauth = row.get('OTPAuth', '').strip() if row.get('OTPAuth', '') else ''

            # Kiểm tra xem mật khẩu có hợp lệ để mã hóa không
            if not password:
                skipped_count += 1
                continue

            # Mã hóa mật khẩu
            try:
                encrypted_password = cipher.encrypt(password.encode()).decode()
            except Exception as e:
                logger.error(f"Error encrypting password for {title}: {e}")
                skipped_count += 1
                continue

            # Kiểm tra trùng lặp dựa trên title, url, và username
            existing_entry = Password.query.filter(
                (Password.title == title) | (Password.title.is_(None) & (title is None)),
                (Password.url == url) | (Password.url.is_(None) & (url is None)),
                (Password.username == username) | (Password.username.is_(None) & (username is None))
            ).first()

            if existing_entry:
                skipped_count += 1
                continue

            # Thêm bản ghi mới nếu không trùng
            password_entry = Password(
                title=title,
                url=url,
                username=username,
                password=encrypted_password,
                notes=notes,
                otpauth=otpauth
            )
            db.session.add(password_entry)
            imported_count += 1

        try:
            db.session.commit()
            # Cung cấp thông tin về kết quả import
            if imported_count > 0 and skipped_count > 0:
                flash(f'CSV imported: {imported_count} entries added, {skipped_count} duplicates skipped')
            elif imported_count > 0:
                flash(f'CSV imported: {imported_count} entries added')
            elif skipped_count > 0:
                flash(f'No new entries added: {skipped_count} duplicates skipped')
            else:
                flash('No entries found in CSV')
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error committing to database: {e}")
            flash(f'Error importing CSV: {str(e)}')

    return redirect(url_for('index', sort_by=request.form.get('sort_by', 'title'),
                            sort_order=request.form.get('sort_order', 'asc')))


@app.route('/clear_db', methods=['POST'])
def clear_db():
    if 'authenticated' not in session:
        return redirect(url_for('login'))
    try:
        # Delete all records from Image and Password tables
        db.session.query(Image).delete()
        db.session.query(Password).delete()
        db.session.commit()
        flash('Database cleared successfully')
    except Exception as e:
        db.session.rollback()
        flash(f'Error clearing database: {str(e)}')
    return redirect(url_for('index', sort_by='title', sort_order='asc'))


# Other routes remain unchanged
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form['password']
        _, login_password = load_config()
        if password == login_password:
            session['authenticated'] = True
            return redirect(url_for('index'))
        else:
            flash('Invalid password')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('authenticated', None)
    return redirect(url_for('login'))


@app.route('/change_key', methods=['GET', 'POST'])
def change_key():
    if 'authenticated' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        old_key = request.form['old_key']
        new_key = request.form['new_key']
        new_login_password = request.form['new_login_password']

        # Kiểm tra key cũ
        old_cipher = get_cipher(old_key)
        if not old_cipher:
            flash('Invalid old encryption key')
            return redirect(url_for('change_key'))
        passwords = Password.query.all()
        try:
            # Thử giải mã một mật khẩu để kiểm tra key cũ
            if passwords:
                old_cipher.decrypt(passwords[0].password.encode())
        except InvalidToken:
            flash('Invalid old encryption key')
            return redirect(url_for('change_key'))

        # Cập nhật key và mật khẩu đăng nhập
        with open('config.txt', 'w') as f:
            f.write(f'ENCRYPTION_KEY={new_key}\nLOGIN_PASSWORD={new_login_password}\n')

        # Giải mã và mã hóa lại tất cả mật khẩu
        new_cipher = get_cipher(new_key)
        if not new_cipher:
            flash('Failed to initialize new cipher')
            return redirect(url_for('change_key'))
        for password in passwords:
            try:
                decrypted_password = old_cipher.decrypt(password.password.encode()).decode()
                password.password = new_cipher.encrypt(decrypted_password.encode()).decode()
            except InvalidToken:
                flash(f'Failed to decrypt password for {password.title}')
                return redirect(url_for('change_key'))
        db.session.commit()
        # Cập nhật cipher toàn cục
        global cipher
        cipher = new_cipher
        flash('Encryption key and login password updated successfully')
        return redirect(url_for('index'))

    return render_template('change_key.html')


@app.route('/export')
def export():
    if 'authenticated' not in session:
        return redirect(url_for('login'))

    # Tạo thư mục tạm thời bằng tempfile
    temp_dir = tempfile.mkdtemp(prefix='temp_export_')
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    try:
        # Tạo file CSV
        csv_path = os.path.join(temp_dir, 'passwords.csv')
        with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Title', 'URL', 'Username', 'Password', 'Notes'])
            passwords = Password.query.all()
            for password in passwords:
                try:
                    decrypted_password = cipher.decrypt(password.password.encode()).decode()
                except InvalidToken:
                    decrypted_password = 'Error: Invalid key'
                writer.writerow([
                    password.title,
                    password.url or '',
                    password.username or '',
                    decrypted_password,
                    password.notes or ''
                ])
                # Lưu hình ảnh vào thư mục con theo title
                if password.images:
                    title_dir = os.path.join(temp_dir, secure_filename(password.title))
                    os.makedirs(title_dir, exist_ok=True)
                    for image in password.images:
                        ext = os.path.splitext(image.filename)[1].lower()
                        mimetype_to_ext = {
                            'image/jpeg': '.jpg',
                            'image/png': '.png',
                            'image/gif': '.gif'
                        }
                        expected_ext = mimetype_to_ext.get(image.mimetype, '.bin')
                        if not ext:
                            filename = image.filename + expected_ext
                        elif ext != expected_ext:
                            logger.warning(
                                f"Extension mismatch for {image.filename}: expected {expected_ext}, got {ext}")
                            filename = os.path.splitext(image.filename)[0] + expected_ext
                        else:
                            filename = image.filename
                        image_path = os.path.join(title_dir, filename)
                        try:
                            with open(image_path, 'wb') as f:
                                f.write(image.data)
                        except Exception as e:
                            logger.error(f"Error writing image {filename}: {e}")

        # Tạo file ZIP
        zip_path = f'export_{timestamp}.zip'
        try:
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                zipf.write(csv_path, 'passwords.csv')
                for root, _, files in os.walk(temp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, temp_dir)
                        zipf.write(file_path, arcname)
        except Exception as e:
            logger.error(f"Error creating ZIP file: {e}")
            flash(f"Error creating ZIP file: {str(e)}")
            raise

        # Gửi file ZIP để tải về
        return send_file(
            zip_path,
            as_attachment=True,
            download_name=f'password_export_{timestamp}.zip'
        )

    except Exception as e:
        logger.error(f"Export failed: {str(e)}")
        flash(f"Export failed: {str(e)}")
        return redirect(url_for('index'))

    finally:
        # Xóa thư mục tạm thời
        try:
            shutil.rmtree(temp_dir)
            logger.info(f"Temporary directory {temp_dir} deleted successfully")
        except Exception as e:
            logger.error(f"Error deleting temporary directory {temp_dir}: {e}")

        # Xóa file ZIP
        try:
            if os.path.exists(zip_path):
                os.remove(zip_path)
                logger.info(f"ZIP file {zip_path} deleted successfully")
        except Exception as e:
            logger.error(f"Error deleting ZIP file {zip_path}: {e}")

    return response


@app.route('/add', methods=['GET', 'POST'])
def add():
    if 'authenticated' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        encrypted_password = cipher.encrypt(request.form['password'].encode()).decode()
        password = Password(
            title=request.form['title'],
            url=request.form['url'],
            username=request.form['username'],
            password=encrypted_password,
            notes=request.form['notes'],
            otpauth=request.form['otpauth']
        )
        db.session.add(password)
        db.session.commit()
        flash('Password added successfully')
        return redirect(url_for('index'))
    return render_template('add.html')


@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit(id):
    if 'authenticated' not in session:
        return redirect(url_for('login'))
    password = Password.query.get_or_404(id)
    if request.method == 'POST':
        password.title = request.form['title']
        password.url = request.form['url']
        password.username = request.form['username']
        if request.form['password']:
            password.password = cipher.encrypt(request.form['password'].encode()).decode()
        password.notes = request.form['notes']
        password.otpauth = request.form['otpauth']
        db.session.commit()
        flash('Password updated successfully')
        return redirect(url_for('index'))
    try:
        decrypted_password = cipher.decrypt(password.password.encode()).decode()
    except InvalidToken:
        flash('Invalid encryption key for decryption')
        decrypted_password = ''
    return render_template('edit.html', password=password, decrypted_password=decrypted_password)


@app.route('/delete/<int:id>')
def delete(id):
    if 'authenticated' not in session:
        return redirect(url_for('login'))
    password = Password.query.get_or_404(id)
    try:
        # Xóa tất cả hình ảnh liên quan trước
        for image in password.images:
            db.session.delete(image)
        # Sau đó xóa mật khẩu
        db.session.delete(password)
        db.session.commit()
        flash('Password and associated images deleted successfully')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting password: {str(e)}')
    return redirect(url_for('index'))


@app.route('/visit/<int:id>')
def visit(id):
    if 'authenticated' not in session:
        return redirect(url_for('login'))
    password = Password.query.get_or_404(id)
    return redirect(password.url)


@app.route('/add_image/<int:id>', methods=['POST'])
def add_image(id):
    if 'authenticated' not in session:
        return redirect(url_for('login'))
    password = Password.query.get_or_404(id)
    if 'image' not in request.files:
        flash('No file part')
        return redirect(url_for('edit', id=id))
    file = request.files['image']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('edit', id=id))
    if file:
        original_filename = file.filename
        mimetype = file.mimetype
        if not mimetype.startswith('image/'):
            flash('Invalid image file')
            return redirect(url_for('edit', id=id))
        # Xác định phần mở rộng dựa trên mimetype
        mimetype_to_ext = {
            'image/jpeg': '.jpg',
            'image/png': '.png',
            'image/gif': '.gif'
        }
        expected_ext = mimetype_to_ext.get(mimetype, '.bin')
        # Sử dụng secure_filename cho tên file gốc, nhưng đảm bảo phần mở rộng đúng
        base_filename = secure_filename(os.path.splitext(original_filename)[0])
        if not base_filename:
            base_filename = 'image'
        filename = base_filename + expected_ext
        image_data = file.read()
        image = Image(data=image_data, filename=filename, mimetype=mimetype, password_id=id)
        db.session.add(image)

        # Kiểm tra và thêm "Image uploaded" vào notes nếu chưa có
        if password.notes is not None:
            notes_lines = password.notes.split('\n')
            if 'Image uploaded' not in notes_lines:
                password.notes = password.notes + '\nImage uploaded'
        else:
            password.notes = 'Image uploaded'

        db.session.commit()
        flash('Image uploaded successfully')
    return redirect(url_for('edit', id=id))


@app.route('/delete_image/<int:image_id>')
def delete_image(image_id):
    if 'authenticated' not in session:
        return redirect(url_for('login'))
    image = Image.query.get_or_404(image_id)
    password_id = image.password_id
    password = Password.query.get_or_404(password_id)

    # Xóa ảnh
    db.session.delete(image)

    # Kiểm tra xem password còn ảnh nào không
    remaining_images = Image.query.filter_by(password_id=password_id).count()

    # Nếu không còn ảnh, xóa cụm từ "Image uploaded" khỏi notes
    if remaining_images == 0 and password.notes:
        notes_lines = password.notes.split('\n')
        if 'Image uploaded' in notes_lines:
            notes_lines.remove('Image uploaded')
            # Loại bỏ các dòng rỗng liên tiếp và cập nhật notes
            password.notes = '\n'.join(line for line in notes_lines if line.strip())
            # Nếu notes trở thành rỗng, đặt lại thành None
            if not password.notes.strip():
                password.notes = ''

    db.session.commit()
    flash('Image deleted successfully')
    return redirect(url_for('edit', id=password_id))


@app.route('/image/<int:image_id>')
def get_image(image_id):
    if 'authenticated' not in session:
        return redirect(url_for('login'))
    image = Image.query.get_or_404(image_id)
    return app.response_class(image.data, mimetype=image.mimetype)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)