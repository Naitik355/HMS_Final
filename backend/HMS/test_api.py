import unittest
import json
from app import app, db, User, Room, Booking, Payment
from flask_login import login_user, logout_user
from werkzeug.security import generate_password_hash
import os

class TestAPI(unittest.TestCase):
    def setUp(self):
        """Set up test environment"""
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
        self.app = app.test_client()
        with app.app_context():
            # Drop all tables and recreate them
            db.drop_all()
            db.create_all()
            
            # Create test admin user
            admin = User(username="testadmin", email="admin@test.com", role="admin")
            admin.set_password("admin123")
            db.session.add(admin)
            
            # Create test regular user
            user = User(username="testuser1", email="user1@test.com", role="user")
            user.set_password("user123")
            db.session.add(user)
            
            db.session.commit()
            self.admin_id = admin.id
            self.user_id = user.id

    def tearDown(self):
        """Clean up after tests"""
        with app.app_context():
            db.session.remove()
            db.drop_all()
            # Remove test database file
            if os.path.exists('test.db'):
                os.remove('test.db')

    def test_1_signup(self):
        """Test user signup"""
        response = self.app.post('/api/signup',
                               data=json.dumps({
                                   'username': 'newuser',
                                   'email': 'new@test.com',
                                   'password': 'newpass123',
                                   'role': 'user'
                               }),
                               content_type='application/json')
        self.assertEqual(response.status_code, 201)
        data = json.loads(response.data)
        self.assertEqual(data['message'], 'User registered successfully')

    def test_2_login(self):
        """Test user login"""
        response = self.app.post('/api/login',
                               data=json.dumps({
                                   'email': 'user1@test.com',
                                   'password': 'user123',
                                   'role': 'user'
                               }),
                               content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['message'], 'Login successful')

    def test_3_room_operations(self):
        """Test room CRUD operations"""
        # Login as admin
        self.app.post('/api/login',
                     data=json.dumps({
                         'email': 'admin@test.com',
                         'password': 'admin123',
                         'role': 'admin'
                     }),
                     content_type='application/json')

        # Create room
        response = self.app.post('/api/rooms',
                               data=json.dumps({
                                   'hostel_name': 'Test Hostel',
                                   'rating': 4.5,
                                   'city': 'Test City',
                                   'image': 'test.jpg'
                               }),
                               content_type='application/json')
        self.assertEqual(response.status_code, 201)
        data = json.loads(response.data)
        room_id = data['id']

        # Get all rooms
        response = self.app.get('/api/rooms')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(len(data), 1)

        # Get single room
        response = self.app.get(f'/api/rooms/{room_id}')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['hostel_name'], 'Test Hostel')

    def test_4_booking_operations(self):
        """Test booking operations"""
        # Login as regular user
        self.app.post('/api/login',
                     data=json.dumps({
                         'email': 'user1@test.com',
                         'password': 'user123',
                         'role': 'user'
                     }),
                     content_type='application/json')

        # Create a room first (as admin)
        self.app.post('/api/login',
                     data=json.dumps({
                         'email': 'admin@test.com',
                         'password': 'admin123',
                         'role': 'admin'
                     }),
                     content_type='application/json')
        response = self.app.post('/api/rooms',
                               data=json.dumps({
                                   'hostel_name': 'Test Hostel',
                                   'rating': 4.5,
                                   'city': 'Test City',
                                   'image': 'test.jpg'
                               }),
                               content_type='application/json')
        room_id = json.loads(response.data)['id']

        # Login back as user
        self.app.post('/api/login',
                     data=json.dumps({
                         'email': 'user1@test.com',
                         'password': 'user123',
                         'role': 'user'
                     }),
                     content_type='application/json')

        # Create booking
        response = self.app.post('/api/bookings',
                               data=json.dumps({
                                   'room_id': room_id
                               }),
                               content_type='application/json')
        self.assertEqual(response.status_code, 201)
        data = json.loads(response.data)
        booking_id = data['id']

        # Get bookings
        response = self.app.get('/api/bookings')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(len(data), 1)

    def test_5_payment_operations(self):
        """Test payment operations"""
        # Login as user
        self.app.post('/api/login',
                     data=json.dumps({
                         'email': 'user1@test.com',
                         'password': 'user123',
                         'role': 'user'
                     }),
                     content_type='application/json')

        # Create payment
        response = self.app.post('/api/payments',
                               data=json.dumps({
                                   'amount': 1000,
                                   'method': 'credit_card'
                               }),
                               content_type='application/json')
        self.assertEqual(response.status_code, 201)
        data = json.loads(response.data)
        payment_id = data['id']

        # Get payments
        response = self.app.get('/api/payments')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(len(data), 1)

    def test_6_logout(self):
        """Test logout"""
        # Login first
        self.app.post('/api/login',
                     data=json.dumps({
                         'email': 'user1@test.com',
                         'password': 'user123',
                         'role': 'user'
                     }),
                     content_type='application/json')

        # Logout
        response = self.app.post('/api/logout')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['message'], 'Logged out successfully')

if __name__ == '__main__':
    unittest.main() 