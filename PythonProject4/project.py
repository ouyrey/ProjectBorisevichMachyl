from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, BooleanField
from wtforms.validators import DataRequired, Length, Email, ValidationError, EqualTo
from datetime import datetime, timedelta
import os
import uuid
import hashlib
from functools import wraps

# App configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fileshare.db'
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size
app.config['BANNED_EXTENSIONS'] = {'exe', 'sh', 'php', 'js', 'py', 'bat', 'cmd'}

@app.context_processor
def inject_datetime():
    return {'datetime': datetime}

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    full_name = db.Column(db.String(120))
    avatar = db.Column(db.String(120))
    role = db.Column(db.String(20), default='user')  # 'admin', 'user'
    registered_on = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    files = db.relationship('File', backref='owner', lazy=True)
    download_links = db.relationship('DownloadLink', backref='creator', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_name = db.Column(db.String(255), nullable=False)
    storage_name = db.Column(db.String(36), nullable=False)  # UUID
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.Text)
    size = db.Column(db.Integer)
    md5_hash = db.Column(db.String(32))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    download_links = db.relationship('DownloadLink', backref='file', lazy=True)


class DownloadLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(36), unique=True, nullable=False)  # UUID
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    download_count = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    full_name = StringField('Full Name')
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already taken')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered')


class FileUploadForm(FlaskForm):
    file = FileField('File', validators=[DataRequired()])
    description = TextAreaField('Description')
    submit = SubmitField('Upload')


class FileEditForm(FlaskForm):
    description = TextAreaField('Description')
    submit = SubmitField('Update')


class ProfileForm(FlaskForm):
    full_name = StringField('Full Name')
    email = StringField('Email', validators=[Email()])
    submit = SubmitField('Update Profile')


class DownloadLinkForm(FlaskForm):
    submit = SubmitField('Generate Download Link')


# Helper functions
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() not in app.config['BANNED_EXTENSIONS']


def calculate_md5(file_stream):
    md5 = hashlib.md5()
    for chunk in iter(lambda: file_stream.read(4096), b''):
        md5.update(chunk)
    file_stream.seek(0)
    return md5.hexdigest()


@app.template_filter('time_ago')
def time_ago(dt):
    now = datetime.utcnow()
    diff = now - dt

    if diff.days > 365:
        return f"{diff.days // 365} years ago"
    if diff.days > 30:
        return f"{diff.days // 30} months ago"
    if diff.days > 0:
        return f"{diff.days} days ago"
    if diff.seconds > 3600:
        return f"{diff.seconds // 3600} hours ago"
    if diff.seconds > 60:
        return f"{diff.seconds // 60} minutes ago"
    return "just now"

def generate_unique_filename(filename):
    ext = filename.rsplit('.', 1)[1].lower()
    unique_name = str(uuid.uuid4())
    return f"{unique_name}.{ext}"


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)

    return decorated_function


# User loader function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/dashboard')
@login_required
def dashboard():
    files = File.query.filter_by(user_id=current_user.id).all()
    links = DownloadLink.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', files=files, links=links, datetime=datetime)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            user.last_login = datetime.utcnow()
            db.session.commit()
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password', 'danger')

    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            full_name=form.full_name.data
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/profile')
@login_required
def profile():
    form = ProfileForm(obj=current_user)
    return render_template('profile.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/file/<int:file_id>')
@login_required
def view_file(file_id):
    file = File.query.get_or_404(file_id)

    if file.user_id != current_user.id and current_user.role != 'admin':
        abort(403)

    return render_template('file_details.html', file=file)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    form = FileUploadForm()
    if form.validate_on_submit():
        file = form.file.data
        if file and allowed_file(file.filename):
            # Calculate file hash
            file_stream = file.stream
            file_hash = calculate_md5(file_stream)

            # Check if file already exists
            existing_file = File.query.filter_by(md5_hash=file_hash, user_id=current_user.id).first()
            if existing_file:
                flash('This file already exists in your storage', 'warning')
                return redirect(url_for('upload_file'))

            # Generate unique filename
            original_name = secure_filename(file.filename)
            storage_name = generate_unique_filename(original_name)

            # Save file
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], storage_name)
            file.save(file_path)

            # Get file size
            file_size = os.path.getsize(file_path)

            # Create file record
            new_file = File(
                original_name=original_name,
                storage_name=storage_name,
                description=form.description.data,
                size=file_size,
                md5_hash=file_hash,
                user_id=current_user.id
            )
            db.session.add(new_file)
            db.session.commit()

            flash('File uploaded successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid file type', 'danger')

    return render_template('upload.html', form=form)


@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)

    if current_user.role == 'admin':
        abort(403, description="Администраторы не могут скачивать файлы пользователей")

    if file.user_id != current_user.id:
        abort(403)

    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        file.storage_name,
        as_attachment=True,
        download_name=file.original_name
    )


@app.route('/file/<int:file_id>/share', methods=['GET', 'POST'])
@login_required
def generate_download_link(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id and current_user.role != 'admin':
        abort(403)

    form = DownloadLinkForm()
    if form.validate_on_submit():
        # Create a new download link
        link = DownloadLink(
            token=str(uuid.uuid4()),
            expires_at=datetime.utcnow() + timedelta(hours=12),
            file_id=file.id,
            user_id=current_user.id
        )
        db.session.add(link)
        db.session.commit()
        flash('Download link created!', 'success')
        return redirect(url_for('view_file', file_id=file.id))

    return render_template('generate_link.html', file=file, form=form)


@app.route('/download/<token>')
def download_via_link(token):
    link = DownloadLink.query.filter_by(token=token).first_or_404()

    if current_user.is_authenticated and current_user.role == 'admin':
        abort(403, description="Администраторы не могут скачивать файлы через ссылки")

    if not link.is_active or link.expires_at < datetime.utcnow():
        abort(410)

    link.download_count += 1
    db.session.commit()

    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        link.file.storage_name,
        as_attachment=True,
        download_name=link.file.original_name
    )

@app.route('/file/<int:file_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_file(file_id):
    file = File.query.get_or_404(file_id)

    if file.user_id != current_user.id and current_user.role != 'admin':
        abort(403)

    form = FileEditForm(obj=file)
    if form.validate_on_submit():
        file.description = form.description.data
        db.session.commit()
        flash('File updated successfully!', 'success')
        return redirect(url_for('view_file', file_id=file.id))

    return render_template('edit_file.html', file=file, form=form)

@app.route('/file/<int:file_id>/delete', methods=['POST'])
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id and current_user.role != 'admin':
        abort(403)
    # Delete the physical file
    try:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file.storage_name))
    except OSError:
        pass

    # Delete the database record
    db.session.delete(file)
    db.session.commit()

    flash('File deleted successfully', 'success')
    return redirect(url_for('dashboard'))


@app.route('/admin')
@admin_required
def admin_dashboard():
    # User statistics
    users_count = User.query.count()
    new_users_7d = User.query.filter(
        User.registered_on >= datetime.utcnow() - timedelta(days=7)
    ).count()

    # File statistics
    files_count = File.query.count()
    files_30d = File.query.filter(
        File.upload_date >= datetime.utcnow() - timedelta(days=30)
    ).count()
    files_30d_percent = min(100, files_30d / max(1, files_count)) * 100

    # Storage statistics
    total_size = db.session.query(db.func.sum(File.size)).scalar() or 0
    storage_limit = 10 * 1024 * 1024 * 1024  # 10GB
    storage_percent = min(100, (total_size / storage_limit) * 100)

    # Link statistics
    links_count = DownloadLink.query.count()
    active_links = DownloadLink.query.filter(
        DownloadLink.is_active == True,
        DownloadLink.expires_at >= datetime.utcnow()
    ).count()
    active_links_percent = min(100, active_links / max(1, links_count) * 100)

    # Recent activity (simplified example)
    recent_activity = [
        {
            'action': 'File Upload',
            'details': 'example.txt',
            'user': current_user,
            'timestamp': datetime.utcnow() - timedelta(minutes=15)
        },
        {
            'action': 'User Registration',
            'details': 'newuser',
            'user': current_user,
            'timestamp': datetime.utcnow() - timedelta(hours=2)
        }
    ]

    return render_template(
        'admin_dashboard.html',
        users_count=users_count,
        new_users_7d=new_users_7d,
        files_count=files_count,
        files_30d=files_30d,
        files_30d_percent=files_30d_percent,
        total_size=total_size,
        storage_percent=storage_percent,
        links_count=links_count,
        active_links=active_links,
        active_links_percent=active_links_percent,
        recent_activity=recent_activity
    )

@app.route('/admin/users')
@admin_required
def admin_users():
    search_query = request.args.get('q', '')
    if search_query:
        users = User.query.filter(
            (User.username.ilike(f'%{search_query}%')) |
            (User.email.ilike(f'%{search_query}%')) |
            (User.full_name.ilike(f'%{search_query}%'))
        ).order_by(User.username).all()
    else:
        users = User.query.order_by(User.username).all()
    return render_template('admin.html', users=users)

@app.route('/admin/files')
@admin_required
def admin_files():
    search_query = request.args.get('q', '')
    if search_query:
        files = File.query.filter(
            (File.original_name.ilike(f'%{search_query}%')) |
            (File.description.ilike(f'%{search_query}%'))
        ).join(User).order_by(File.upload_date.desc()).all()
    else:
        files = File.query.join(User).order_by(File.upload_date.desc()).all()
    return render_template('files.html', files=files)

@app.route('/admin/links')
@admin_required
def admin_links():
    search_query = request.args.get('q', '')
    if search_query:
        links = DownloadLink.query.join(File).filter(
            (File.original_name.ilike(f'%{search_query}%')) |
            (DownloadLink.token.ilike(f'%{search_query}%'))
        ).order_by(DownloadLink.expires_at.desc()).all()
    else:
        links = DownloadLink.query.order_by(DownloadLink.expires_at.desc()).all()
    return render_template('links.html', links=links)


@app.route('/admin/user/<int:user_id>/files')
@admin_required
def admin_user_files(user_id):
    user = User.query.get_or_404(user_id)
    search_query = request.args.get('q', '')

    query = File.query.filter_by(user_id=user.id)

    if search_query:
        query = query.filter(
            (File.original_name.ilike(f'%{search_query}%')) |
            (File.description.ilike(f'%{search_query}%'))
        )

    files = query.order_by(File.upload_date.desc()).all()
    total_size = sum(f.size for f in files) if files else 0

    return render_template(
        'user_files.html',
        user=user,
        files=files,
        total_size=total_size,
        search_query=search_query
    )

@app.route('/admin/user/<int:user_id>/links')
@admin_required
def admin_user_links(user_id):
    user = User.query.get_or_404(user_id)
    links = DownloadLink.query.filter_by(user_id=user.id).order_by(DownloadLink.expires_at.desc()).all()
    return render_template('user_links.html', user=user, links=links)

@app.route('/admin/file/<int:file_id>/links')
@admin_required
def admin_file_links(file_id):
    file = File.query.get_or_404(file_id)
    links = DownloadLink.query.filter_by(file_id=file.id).order_by(DownloadLink.expires_at.desc()).all()
    return render_template('file_links.html', file=file, links=links)

@app.route('/admin/link/<int:link_id>/deactivate', methods=['POST'])
@admin_required
def admin_deactivate_link(link_id):
    link = DownloadLink.query.get_or_404(link_id)
    link.is_active = False
    db.session.commit()
    flash('Link has been deactivated', 'success')
    return redirect(request.referrer or url_for('admin_links'))

# Initialize database
@app.before_request
def create_tables():
    db.create_all()
    # Create admin user if not exists
    if not User.query.filter_by(role='admin').first():
        admin = User(
            username='admin',
            email='admin@example.com',
            role='admin'
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()


if __name__ == '__main__':
    app.run(debug=True)