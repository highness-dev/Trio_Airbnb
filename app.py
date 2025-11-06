from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, g, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import logging
import traceback
import secrets

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'trio-airbnb-secret-key-2023')

# Session configuration
app.config.update(
    SESSION_COOKIE_NAME='trio_airbnb_session',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=24),
    SESSION_REFRESH_EACH_REQUEST=True
)

# -----------------------
# Upload configuration
# -----------------------
UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Database configuration - with fallback to SQLite
from sqlalchemy import create_engine

# Initialize db *once*
db = SQLAlchemy()

try:
    # Try PostgreSQL first
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg://postgres:highness@localhost:5432/trio_airbnb'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Test connection before binding db to app
    engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
    engine.connect()
    print("✅ PostgreSQL connection successful")

except Exception as e:
    print(f"❌ PostgreSQL connection failed: {e}")
    print("⚠️ Falling back to SQLite database")

    # Fall back to SQLite
    basedir = os.path.abspath(os.path.dirname(__file__))
    app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(basedir, 'trio_airbnb.db')}"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    print("✅ SQLite database configured")

# Now finally bind db to app
db.init_app(app)

# Initialize migrations AFTER db.init_app
from flask_migrate import Migrate
migrate = Migrate(app, db)


# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    reset_token = db.Column(db.String(255), nullable=True)


    # Relationship with bookings
    bookings = db.relationship('Booking', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.name}>'


# Property model
class Property(db.Model):
    __tablename__ = 'property'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Float, nullable=False)
    property_type = db.Column(db.String(50), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    # store relative path to static folder, e.g. 'uploads/filename.jpg' or a full external URL
    image_url = db.Column(db.String(255), nullable=True)
    image_filename = db.Column(db.String(255), nullable=True)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def image(self):
        """
        Return the stored image path.
        - If image_filename is used (legacy), return 'uploads/<filename>'.
        - Else return image_url (which may be 'uploads/...' or an absolute URL).
        Templates should use: url_for('static', filename=property.image) when image is relative.
        """
        if self.image_filename:
            return f"uploads/{self.image_filename}"
        return self.image_url

    def __repr__(self):
        return f"<Property {self.title}>"


# Booking model
class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    property_id = db.Column(db.Integer, db.ForeignKey('property.id'), nullable=False)
    check_in = db.Column(db.Date, nullable=False)
    check_out = db.Column(db.Date, nullable=False)
    guests = db.Column(db.Integer, nullable=False)
    guest_name = db.Column(db.String(100), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    property = db.relationship('Property', backref='booked_by', lazy=True)

    def __repr__(self):
        return f'<Booking {self.guest_name}>'


# Create tables and sample data
def init_db():
    try:
        with app.app_context():
            print("Attempting to connect to database...")

            # Test connection first
            try:
                db.engine.connect()
                print("✅ Database connection successful")
            except Exception as e:
                print(f"❌ Database connection failed: {e}")
                print("Please check:")
                print("1. Is PostgreSQL running?")
                print("2. Does the database 'trio_airbnb' exist?")
                print("3. Are the username and password correct?")
                print("4. Is PostgreSQL listening on port 5432?")
                return False

            # Check if database exists first
            from sqlalchemy import inspect
            inspector = inspect(db.engine)

            tables_to_check = ['user', 'property', 'booking']
            existing_tables = []

            for table in tables_to_check:
                if inspector.has_table(table):
                    existing_tables.append(table)
                    print(f"✅ Table '{table}' exists")
                else:
                    print(f"❌ Table '{table}' does not exist")

            if len(existing_tables) < len(tables_to_check):
                print("Creating missing tables...")
                db.create_all()
                print("✅ Database tables created successfully")
            else:
                print("✅ All database tables already exist")

            # Insert sample properties if none exist

    except Exception as e:
        print(f"❌ Error initializing database: {e}")
        print("Full error details:")
        traceback.print_exc()
        return False


# Initialize the database
init_db()


# Routes
from functools import wraps


@app.before_request
def load_logged_in_user():
    if 'user_id' in session and session['user_id'] != 'admin':
        g.user = User.query.get(session['user_id'])
    elif session.get('user_id') == 'admin':
        # pseudo-user for admin sessions
        g.user = None
    else:
        g.user = None


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If you later add role column to User, update logic here.
        if session.get('user_id') == 'admin':
            return f(*args, **kwargs)
        # fallback: if there's a logged in user and has role 'admin' (future)
        if g.user and getattr(g.user, 'role', None) == 'admin':
            return f(*args, **kwargs)

        flash("Admin access only", "error")
        return redirect(url_for('index'))
    return decorated_function


@app.route('/')
def index():
    try:
        # Test database connection first
        try:
            db.engine.connect()
        except Exception as e:
            error_msg = f"Database connection error: {str(e)}. Please check if PostgreSQL is running."
            print(f"❌ {error_msg}")
            return render_template('error.html', error_message=error_msg)

        properties = Property.query.order_by(Property.date_created.desc()).all()
        return render_template('index.html', properties=properties)

    except Exception as e:
        error_msg = f"Error loading properties: {str(e)}. Please check database connection."
        print(f"❌ {error_msg}")
        return render_template('error.html', error_message=error_msg)


@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash("Please log in to view your profile", "error")
        return redirect(url_for('login'))

    try:
        user = User.query.get(session['user_id'])
        bookings = Booking.query.filter_by(user_id=session['user_id']).order_by(Booking.date_created.desc()).all()

        return render_template('profile.html', user=user, bookings=bookings, datetime=datetime)
    except Exception as e:
        print(f"Error loading profile: {e}")
        flash("Error loading profile. Please try again.", "error")
        return redirect(url_for('index'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        # Define your admin login details here
        ADMIN_EMAIL = "admin@trioairbnb.com"
        ADMIN_PASSWORD = "admin123"  # you can store this hashed later

        # ✅ Check if this is the admin login (hardcoded)
        if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
            session['user_id'] = 'admin'
            session['user_name'] = 'Admin'
            flash("Welcome, Admin 👑", "success")
            # Force admin to admin dashboard only
            return redirect(url_for('admin', password='admin123'))

        # ✅ Normal user login
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_name'] = user.name
            session.permanent = True

            flash(f"Welcome back, {user.name}!", "success")

            next_url = session.pop('next_url', None)
            if next_url:
                return redirect(next_url)
            return redirect(url_for('index'))

        else:
            flash("Invalid email or password", "error")
            return render_template('login.html')

    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])

        # Check if user already exists
        if User.query.filter_by(email=email).first():
            flash("Email already registered", "error")
            return render_template('signup.html')

        new_user = User(name=name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()

        session['user_id'] = new_user.id
        session['user_name'] = new_user.name

        flash("Account created successfully! Welcome to Trio Airbnb.", "success")
        return redirect(url_for('index'))

    return render_template('signup.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if not user:
            flash("No account found with that email.", "error")
            return redirect(url_for('forgot_password'))

        # create reset token
        token = secrets.token_urlsafe(32)
        user.reset_token = token
        db.session.commit()

        # temp "email" output (shows in console)
        print("\n===== PASSWORD RESET LINK =====")
        print(url_for('reset_password', token=token, _external=True))
        print("================================\n")

        flash("We sent you a password reset link. Check your email.", "success")
        return redirect(url_for('login'))

    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()

    if not user:
        return "Invalid or expired reset link."

    if request.method == 'POST':
        new_password = request.form.get('password')
        user.password = generate_password_hash(new_password)
        user.reset_token = None
        db.session.commit()

        flash("Password updated successfully. You can now log in.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html')



@app.route('/search', methods=['POST'])
def search_properties():
    try:
        location = request.form.get('location', '')

        # Basic search implementation
        if location:
            properties = Property.query.filter(
                Property.location.ilike(f'%{location}%')
            ).all()
        else:
            properties = Property.query.all()

        return render_template('index.html', properties=properties, search_location=location)
    except Exception as e:
        print(f"Search error: {e}")
        properties = Property.query.all()
        return render_template('index.html', properties=properties, error="Search failed. Please try again.")


@app.route('/book', methods=['POST'])
def book_property():
    print(f"DEBUG: Booking attempt - Session: {dict(session)}")

    if 'user_id' not in session:
        print("DEBUG: No user_id in session, redirecting to login")
        # Store the intended destination in session
        session['next_url'] = request.url
        return redirect(url_for('login'))

    try:
        property_id = request.form.get('property_id')
        check_in = datetime.strptime(request.form.get('check_in'), '%Y-%m-%d').date()
        check_out = datetime.strptime(request.form.get('check_out'), '%Y-%m-%d').date()
        guests = request.form.get('guests', 1)
        guest_name = request.form.get('guest_name', session.get('user_name', ''))

        # Get property details for the success message
        property = Property.query.get(property_id)
        if not property:
            flash("Property not found", "error")
            return redirect(url_for('index'))

        # Create new booking
        new_booking = Booking(
            user_id=session['user_id'],
            property_id=property_id,
            check_in=check_in,
            check_out=check_out,
            guests=guests,
            guest_name=guest_name
        )

        db.session.add(new_booking)
        db.session.commit()

        print(f"DEBUG: Booking created for user {session['user_id']}")

        # Add success message
        flash(f"Successfully booked {property.title} from {check_in} to {check_out}!", "success")
        return redirect(url_for('index'))

    except Exception as e:
        print(f"Booking error: {e}")
        flash("There was an error processing your booking. Please try again.", "error")
        return redirect(url_for('index'))


@app.route('/debug_session')
def debug_session():
    return f"""
    <h1>Session Debug Info</h1>
    <p>Session ID: {session.sid}</p>
    <p>Session Data: {dict(session)}</p>
    <p>User ID in session: {session.get('user_id', 'NOT SET')}</p>
    <p>User Name in session: {session.get('user_name', 'NOT SET')}</p>
    <p>Permanent Session: {session.permanent}</p>
    <p><a href="/">Return to Home</a></p>
    """


@app.before_request
def check_session():
    # Skip session check for static files and auth pages
    if request.endpoint in ['static', 'login', 'signup', 'debug_session', 'debug_db', 'test_connection']:
        return

    print(f"DEBUG: Before request - Session: {dict(session)}")
    print(f"DEBUG: User ID in session: {session.get('user_id')}")


@app.route('/admin')
def admin():
    # Basic authentication for admin
    if request.args.get('password') != 'admin123' and session.get('user_id') != 'admin':
        return "Unauthorized", 401

    try:
        users = User.query.all()
        bookings = Booking.query.all()
        properties = Property.query.all()

        # Add statistics
        stats = {
            'total_users': len(users),
            'total_bookings': len(bookings),
            'total_properties': len(properties),
            'recent_bookings': Booking.query.order_by(Booking.date_created.desc()).limit(5).all()
        }

        return render_template('admin.html', users=users, bookings=bookings,
                               properties=properties, stats=stats)
    except Exception as e:
        print(f"Admin error: {e}")
        return "Error loading admin page. Please check database connection."


# Route to add a property from admin dashboard
@app.route('/add_property', methods=['POST'])
def add_property():
    # Restrict to admin via session or password query param
    if session.get('user_id') != 'admin' and request.args.get('password') != 'admin123':
        flash("Unauthorized: admin only", "error")
        return redirect(url_for('admin', password='admin123'))

    try:
        title = request.form.get('title', '').strip()
        property_type = request.form.get('property_type', '').strip()
        location = request.form.get('location', '').strip()
        price_raw = request.form.get('price', '').strip()
        description = request.form.get('description', '').strip()  # ✅ keep description from the form

        # Basic validation
        if not title or not property_type or not location or not price_raw:
            flash("Please provide title, type, location and price.", "error")
            return redirect(url_for('admin', password='admin123'))

        try:
            price = float(price_raw)
        except ValueError:
            flash("Price must be a number.", "error")
            return redirect(url_for('admin', password='admin123'))

        # ---- image handling (correctly inside the try block) ----
        image = request.files.get('image')
        db_image_path = None

        if image and image.filename != '':
            if allowed_file(image.filename):
                # create a safe, unique filename
                filename = secure_filename(f"{int(datetime.utcnow().timestamp())}_{image.filename}")
                save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image.save(save_path)
                # Store a path relative to static folder (no leading slash)
                db_image_path = f'uploads/{filename}'
            else:
                flash("Invalid image type. Allowed: png, jpg, jpeg, gif, webp", "error")
                return redirect(url_for('admin', password='admin123'))
        else:
            # no image uploaded — set a default image (ensure static/uploads/default.jpg exists)
            db_image_path = 'uploads/default.jpg'

        # Create and save property with image + description
        new_property = Property(
            title=title,
            property_type=property_type,
            location=location,
            price=price,
            description=description,
            image_url=db_image_path  # make sure your templates use url_for('static', filename=property.image_url) for local files
        )

        db.session.add(new_property)
        db.session.commit()

        flash("✅ Property added successfully!", "success")
        return redirect(url_for('admin', password='admin123'))

    except Exception as e:
        print(f"Error adding property: {e}")
        traceback.print_exc()
        flash("There was an error adding the property. See server logs.", "error")
        return redirect(url_for('admin', password='admin123'))


# Delete user (admin only)
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    # Basic authentication for admin
    if request.args.get('password') != 'admin123' and session.get('user_id') != 'admin':
        return "Unauthorized", 401

    try:
        user = User.query.get_or_404(user_id)

        # Delete all bookings by this user first
        Booking.query.filter_by(user_id=user_id).delete()

        # Delete the user
        db.session.delete(user)
        db.session.commit()

        flash(f"User {user.name} and all their bookings have been deleted", "success")
        return redirect(url_for('admin', password='admin123'))

    except Exception as e:
        print(f"Error deleting user: {e}")
        flash("Error deleting user", "error")
        return redirect(url_for('admin', password='admin123'))


# Delete booking (admin only)
@app.route('/admin/delete_booking/<int:booking_id>', methods=['POST'])
def delete_booking(booking_id):
    # Basic authentication for admin
    if request.args.get('password') != 'admin123' and session.get('user_id') != 'admin':
        return "Unauthorized", 401

    try:
        booking = Booking.query.get_or_404(booking_id)
        db.session.delete(booking)
        db.session.commit()

        flash("Booking deleted successfully", "success")
        return redirect(url_for('admin', password='admin123'))

    except Exception as e:
        print(f"Error deleting booking: {e}")
        flash("Error deleting booking", "error")
        return redirect(url_for('admin', password='admin123'))


# Delete property (admin only)
@app.route('/admin/delete_property/<int:property_id>', methods=['POST'])
def delete_property(property_id):
    # Basic authentication for admin
    if request.args.get('password') != 'admin123' and session.get('user_id') != 'admin':
        return "Unauthorized", 401

    try:
        property_obj = Property.query.get_or_404(property_id)

        # Delete all bookings for this property first
        Booking.query.filter_by(property_id=property_id).delete()

        # Delete the property
        # If the property has an uploaded image stored in static/uploads, attempt to remove it
        if property_obj.image_url:
            # normalize possible variants
            path = property_obj.image_url.lstrip('/')
            if path.startswith('uploads/'):
                file_path = os.path.join(app.root_path, 'static', path)
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                except Exception as rm_e:
                    print(f"Warning: could not remove image file: {rm_e}")

        db.session.delete(property_obj)
        db.session.commit()

        flash(f"Property {property_obj.title} and all related bookings have been deleted", "success")
        return redirect(url_for('admin', password='admin123'))

    except Exception as e:
        print(f"Error deleting property: {e}")
        flash("Error deleting property", "error")
        return redirect(url_for('admin', password='admin123'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


# Debug routes
@app.route('/debug/db')
def debug_db():
    """Debug page to check database connection"""
    try:
        # Try to get database info
        db_url = app.config['SQLALCHEMY_DATABASE_URI']

        if 'postgresql' in db_url:
            from urllib.parse import urlparse
            parsed = urlparse(db_url)

            db_info = {
                'database': parsed.path[1:],  # Remove leading slash
                'user': parsed.username,
                'password': '***' if parsed.password else 'None',
                'host': parsed.hostname,
                'port': parsed.port,
                'driver': 'PostgreSQL'
            }
        else:
            db_info = {
                'database': 'SQLite',
                'user': 'N/A',
                'password': 'N/A',
                'host': 'N/A',
                'port': 'N/A',
                'driver': 'SQLite'
            }

        # Try to connect
        try:
            db.engine.connect()
            db_info['connection'] = 'SUCCESS'
        except Exception as e:
            db_info['connection'] = f'FAILED: {str(e)}'

        # Check if tables exist
        tables_exist = {}
        try:
            from sqlalchemy import inspect
            inspector = inspect(db.engine)
            tables = ['user', 'property', 'booking']
            for table in tables:
                tables_exist[table] = inspector.has_table(table)
        except Exception as e:
            tables_exist['error'] = str(e)

        return render_template('debug_db.html', db_info=db_info, tables_exist=tables_exist)

    except Exception as e:
        return f"Error in debug_db: {str(e)}"


@app.route('/debug/test_connection')
def test_connection():
    """Simple connection test"""
    try:
        db.engine.connect()
        return "✅ Database connection successful!"
    except Exception as e:
        return f"❌ Database connection failed: {str(e)}"
    
    
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    """
    Serve uploaded files from /static/uploads.
    Use: in templates for local image: <img src="{{ url_for('uploaded_file', filename='cozy.jpg') }}">
    or use url_for('static', filename=property.image_url) if property.image_url is 'uploads/<file>'
    """
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
