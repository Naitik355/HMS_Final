from flask import Flask, render_template, request, jsonify, flash, redirect, url_for, session,send_from_directory
import yagmail
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from werkzeug.exceptions import BadRequest
from flask_cors import CORS
from flask_restful import Api, Resource
from datetime import datetime
from functools import wraps
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
api = Api(app)
CORS(app)


UPLOAD_FOLDER = os.path.join(basedir, 'static', 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hostel.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["SECRET_KEY"] = "Your secret key"

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

login_manager.init_app(app)

login_manager.login_view = "login"

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False)
    role=db.Column(db.String(50),nullable=False,default="user")
    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password)

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

    if not User.query.filter_by(role="admin").first():
        admin_user = User(username="Admin", email="admin@gmail.com", role="admin")
        admin_user.set_password("admin123")
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created with email: admin@gmail.com and password: admin123")

GMAIL_USER = os.getenv("GMAIL_USER", "your-email@gmail.com") 
GMAIL_PASSWORD = os.getenv("GMAIL_PASSWORD", "your-app-password")   

def send_email(to_email, amount):
    subject = "Payment Successful - Hostel Booking"
    body = f"""
    Hello,

    Your payment of Rs. {amount} was successful.

    Thank you for booking with us!

    Regards,
    Hostel Management
    """
    try:
        yag = yagmail.SMTP(GMAIL_USER, GMAIL_PASSWORD)
        yag.send(to=to_email, subject=subject, contents=body)
        print(f"Email sent to {to_email}")
    except Exception as e:
        print(f"Error sending email: {e}")

@app.route('/')
def index():
    rooms = Room.query.all()
    return render_template('index.html', rooms=rooms)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        role=request.form.get('role')

        user = User.query.filter_by(email=email,role=role).first()
        if user and user.check_password(password):
            login_user(user)
            session['user_id'] = user.id
            session['user_name'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login failed. Check your email and password.', 'danger')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get("confirm_password")
        role=request.form.get('role')

        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for("signup"))
        
        if User.query.filter_by(email=email).first():
            flash("Email already exists!", "danger")
            return redirect(url_for("signup"))
        
        new_user = User(username=username, email=email,role=role)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))
    return render_template('signup.html')


@app.route("/logout")
def logout():
    session.pop('user_id', None)
    session.pop('user_name', None)
    logout_user()
    flash('You have been logged out!', 'info')
    return redirect(url_for('index'))

def admin_required(func):
    @wraps(func)
    def wrapper(args,*kwraps):
        if current_user.role!='admin':
            flash("Access denied!","danger")
            return redirect(url_for("index"))
        return func(args,*kwraps)
    return wrapper

@app.route('/admin')
@login_required
@admin_required
def admin():
    return "Welcome Admin"

@app.route('/profile')
@login_required
def profile():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    return render_template('index.html', user=current_user)

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    user_name = session['user_name']
    
    user = User.query.get(user_id)
    
    return render_template('admin_dashboard.html', user=user)

@app.route('/<template>')
def load_template(template):
    return render_template(f"{template}")

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostel_name = db.Column(db.String(100), nullable=False)  
    rating = db.Column(db.Float, nullable=False)  
    city = db.Column(db.String(100), nullable=False)  
    image = db.Column(db.String(255), nullable=True)

    def __repr__(self):
        return f'<Room {self.hostel_name}>'

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'))
    status = db.Column(db.String(50), default="Pending")

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String,nullable=False)
    amount = db.Column(db.Float, nullable=False)
    method = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(50), default='Pending')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    db.create_all()
with app.app_context():
    if Admin.query.count() == 0:
        admin_username = "admin@gmail"
        admin_password = "124"

        hashed_password = generate_password_hash(admin_password)
        new_admin = Admin(username=admin_username, password=hashed_password)

        db.session.add(new_admin)
        db.session.commit()
        print("Admin account created!")

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        admin = Admin.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password, password):
            session['admin_logged_in'] = True
            session['admin_username'] = admin.username
            session['user_id'] = admin.id  # Ensure admin ID is set in session
            session['user_role'] = 'admin'  # Add user role to session for verification
            return redirect(url_for('admin_dashboard'))
        else:
            flash("Invalid Username or Password", "danger")
    
    return render_template('admin_login.html')

@app.route('/admin-logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    return redirect(url_for('index'))

@app.route('/add_room', methods=['GET', 'POST'])
def add_room():
    if request.method == 'POST':
        hostel_name = request.form['hostel_name']
        rating = request.form['rating']
        city = request.form['city']
        image = request.files['image']

        image_filename = None
        if image and allowed_file(image.filename):
            image_filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))

        new_room = Room(
            hostel_name=hostel_name,
            rating=float(rating),
            city=city,
            image=image_filename
        )

        try:
            db.session.add(new_room)
            db.session.commit()
            flash('Room added successfully!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding room: {str(e)}', 'error')

    return render_template('add_room.html')

@app.route('/view-rooms')
def view_rooms():
    rooms = Room.query.filter_by(occupied=False).all()
    return render_template('view_rooms.html', rooms=rooms)

@app.route('/book-room/<int:room_id>', methods=['GET', 'POST'])
def book_room(room_id):
    room = Room.query.get_or_404(room_id)
    
    if request.method == 'POST':
        room.occupied = True
        room.status = 'Occupied'
        db.session.commit()

        flash('Room booked successfully!', 'success')
        return redirect(url_for('view_rooms'))

    return render_template('book_room.html', room=room)

@app.route('/admin-rooms')
def admin_rooms():
    rooms = Room.query.all()
    return render_template('admin_rooms.html', rooms=rooms)

@app.route('/edit-room/<int:room_id>', methods=['GET', 'POST'])
def edit_room(room_id):
    room = Room.query.get_or_404(room_id)

    if request.method == 'POST':
        room.hostel_name = request.form['hostel_name']
        room.rating = request.form['rating']
        room.city = request.form['city']

        image = request.files.get('image')
        if image and allowed_file(image.filename):
            image_filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
            room.image = image_filename

        db.session.commit()

        flash('Room updated successfully!', 'success')
        return redirect(url_for('admin_rooms'))

    return render_template('edit_room.html', room=room)

@app.route('/delete-room/<int:room_id>')
def delete_room(room_id):
    room = Room.query.get(room_id)
    if room:
        db.session.delete(room)
        db.session.commit()

    return redirect(url_for('admin_rooms'))

@app.route('/admin-users')
def admin_users():
    users = User.query.all()
    print(users)
    return render_template('admin_users.html', users=users)

@app.route('/delete-user/<int:user_id>')
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()

    return redirect(url_for('admin_users'))

@app.route('/admin-payments')
def admin_payments():
    payments = Payment.query.all()
    return render_template('admin_payments.html', payments=payments)

@app.route('/confirm-payment/<int:payment_id>')
def confirm_payment(payment_id):
    payment = Payment.query.get(payment_id)
    if payment:
        payment.status = "Successful"
        db.session.commit()

    return redirect(url_for('admin_payments'))

@app.route('/admin-bookings')
def admin_bookings():
    bookings = Booking.query.all()
    return render_template('admin_bookings.html', bookings=bookings)

@app.route('/confirm-booking/<int:booking_id>')
def confirm_booking(booking_id):
    booking = Booking.query.get(booking_id)
    if booking:
        booking.status = 'Confirmed'
        db.session.commit()
        flash('Booking confirmed successfully!', 'success')
    return redirect(url_for('admin_bookings'))

@app.route('/cancel-booking/<int:booking_id>')
def cancel_booking(booking_id):
    booking = Booking.query.get(booking_id)
    if booking:
        booking.status = 'Cancelled'
        db.session.commit()
        flash('Booking cancelled successfully!', 'danger')
    return redirect(url_for('admin_bookings'))

@app.route('/delete-booking/<int:booking_id>')
def delete_booking(booking_id):
    booking = Booking.query.get(booking_id)
    if booking:
        db.session.delete(booking)
        db.session.commit()
        flash('Booking deleted successfully!', 'warning')
    return redirect(url_for('admin_bookings'))

from flask import send_from_directory

@app.route('/payment')
def payment():
    return render_template('payment.html')

@app.route('/process_payment', methods=['POST'])
def process_payment():
    data = request.get_json()
    email = data.get('email')
    amount = data.get('amount')
    method = data.get('method')
    if not email or not amount or not method:
        return jsonify({"message": "Missing required fields"}), 400
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "User not found"}), 404
    payment = Payment(user_id=user.id, amount=amount, method=method, status='Pending')
    db.session.add(payment)
    db.session.commit()
    payment.status = 'Successful'
    db.session.commit()
    return jsonify({"message": "Payment processed successfully!"})

@app.route('/routes')
def list_routes():
    import urllib
    output = []
    for rule in app.url_map.iter_rules():
        methods = ','.join(rule.methods)
        line = urllib.parse.unquote(f"{rule.endpoint}: {methods} {rule}")
        output.append(line)
    return '<br>'.join(output)

class SignUp(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        role = data.get('role', 'user')
        if not all([username, email, password, confirm_password]):
            return {"message": "All fields are required."}, 400
        if password != confirm_password:
            return {"message": "Passwords do not match."}, 400
        if User.query.filter_by(email=email).first():
            return {"message": "Email already exists."}, 400
        new_user = User(username=username, email=email, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        return {"message": "User registered successfully."}, 201

class Login(Resource):
    def post(self):
        data = request.get_json()
        if not data:
            raise BadRequest("No input data")
        username = data.get('username')
        password = data.get('password')
        role = data.get('role', 'user')
        if not username or not password:
            return {'error': 'Username and password are required'}, 400
        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            return {'error': 'Invalid username or password'}, 400
        if role == 'admin' and user.role != 'admin':
            return {'error': 'Unauthorized access. Admin privileges required.'}, 403
        return {'message': 'Login successful'}, 200

class Users(Resource):
    def post(self):
        users = User.query.all()
        if not users:
            return {"message": "No users found."}, 404
        return [
            {'id': user.id, 'username': user.username, 'email': user.email, 'role': user.role}
            for user in users
        ], 200

class UserDetail(Resource):
    @login_required
    def get(self, user_id):
        if current_user.role != 'admin':
            return {'error': 'Unauthorized'}, 403
        user = User.query.get_or_404(user_id)
        return {'id': user.id, 'username': user.username, 'email': user.email, 'role': user.role}, 200

class DeleteUser(Resource):
    def delete(self):
        data = request.get_json()
        user_id = data.get('user_id')
        if not user_id:
            return {'error': 'User ID is required.'}, 400
        user = User.query.get(user_id)
        if not user:
            return {'error': 'User not found.'}, 404
        db.session.delete(user)
        db.session.commit()
        return {'message': 'User deleted successfully.'}, 200

class UpdateUser(Resource):
    @login_required
    def put(self, user_id):
        if current_user.role != 'admin':
            return {'error': 'Unauthorized'}, 403
        user = User.query.get_or_404(user_id)
        data = request.get_json()
        user.username = data.get('username', user.username)
        user.email = data.get('email', user.email)
        user.role = data.get('role', user.role)
        db.session.commit()
        return {'message': 'User updated successfully'}, 200

class AddRoom(Resource):
    def post(self):
        try:
            data = request.get_json()
        except Exception as e:
            return {'error': 'Invalid JSON'}, 400
        hostel_name = data.get('hostel_name')
        rating = data.get('rating')
        city = data.get('city')
        image_name = data.get('image_name')
        if not all([hostel_name, rating, city, image_name]):
            return {'error': 'Missing required fields'}, 400
        try:
            new_room = Room(
                hostel_name=hostel_name,
                rating=float(rating),
                city=city,
                image=image_name
            )
            db.session.add(new_room)
            db.session.commit()
        except Exception as e:
            return {'error': 'Database error'}, 500
        return {
            'message': 'Room added successfully',
            'room_id': new_room.id,
            'image_name': image_name
        }, 201

class Rooms(Resource):
    def get(self):
        rooms = Room.query.all()
        return {
            'rooms': [
                {
                    'id': room.id,
                    'hostel_name': room.hostel_name,
                    'rating': room.rating,
                    'city': room.city,
                    'image': f'http://localhost:8000/media/images/{room.image}' if room.image else None
                }
                for room in rooms
            ]
        }, 200

class Payments(Resource):
    def get(self):
        payments = Payment.query.all()
        return [{
            'username': payment.username,
            'amount': payment.amount,
            'method': payment.method,
            'status': payment.status,
        } for payment in payments], 200

    def post(self):
        data = request.get_json()
        username = data.get('username')
        amount = data.get('amount')
        method = data.get('payment_method')
        if not all([username, amount, method]):
            return {'error': 'Missing required fields'}, 400
        user = User.query.filter_by(username=username).first()
        if not user:
            return {'error': 'User not found'}, 404
        payment = Payment(username=username, amount=amount, method=method, status='Success')
        db.session.add(payment)
        db.session.commit()
        return {'message': 'Payment created successfully', 'payment_id': payment.id}, 201

class DeleteRoom(Resource):
    def delete(self, room_id):
        room = Room.query.get(room_id)
        if not room:
            return {'error': 'Room not found'}, 404
        try:
            db.session.delete(room)
            db.session.commit()
            return {'message': 'Room deleted successfully'}, 200
        except Exception as e:
            db.session.rollback()
            return {'error': f'Error deleting room: {str(e)}'}, 500

class EditRoom(Resource):
    def get(self, room_id):
        room = Room.query.get(room_id)
        if not room:
            return {'error': 'Room not found'}, 404
        return {
            'hostel_name': room.hostel_name,
            'rating': room.rating,
            'city': room.city,
            'image': room.image
        }, 200

    def put(self, room_id):
        room = Room.query.get(room_id)
        if not room:
            return {'error': 'Room not found'}, 404
        data = request.get_json()
        hostel_name = data.get('hostel_name', room.hostel_name)
        rating = data.get('rating', room.rating)
        city = data.get('city', room.city)
        image_name = data.get('image', room.image)
        room.hostel_name = hostel_name
        room.rating = rating
        room.city = city
        room.image = image_name
        try:
            db.session.commit()
            return {'message': 'Room updated successfully'}, 200
        except Exception as e:
            db.session.rollback()
            return {'error': f'Error updating room: {str(e)}'}, 500

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

api.add_resource(SignUp, '/api/signup', endpoint='api_signup')
api.add_resource(Login, '/api/login', endpoint='api_login')
api.add_resource(Users, '/api/users', endpoint='api_users')
api.add_resource(UserDetail, '/api/admin/users/<int:user_id>', endpoint='api_user_detail')
api.add_resource(DeleteUser, '/api/delete_user', endpoint='api_delete_user')
api.add_resource(UpdateUser, '/api/admin/users/<int:user_id>', endpoint='api_update_user')
api.add_resource(AddRoom, '/api/add_rooms', endpoint='api_add_room')
api.add_resource(Rooms, '/api/rooms', endpoint='api_rooms')
api.add_resource(Payments, '/api/payments', endpoint='api_payments')
api.add_resource(DeleteRoom, '/api/delete_rooms/<int:room_id>', endpoint='api_delete_room')
api.add_resource(EditRoom, '/api/edit_rooms/<int:room_id>', endpoint='api_edit_room')
if __name__ == '__main__':
    app.run(debug=True)
