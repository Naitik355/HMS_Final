from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from .models import Room, Payment
from django.contrib.auth.password_validation import validate_password
import json
from .models import Room, Payment
from django.http import JsonResponse
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.files.storage import FileSystemStorage
from django.core.files.storage import default_storage
from django.core.files import File
from django.http import HttpResponseBadRequest
from django.contrib.auth import login, authenticate
import os
from django.conf import settings
from django.contrib.auth import logout as logout_auth
from django.core.exceptions import ValidationError
import requests
from django.utils.crypto import get_random_string
from django.contrib.auth import get_user_model
User = get_user_model()

def HMS_app1_view(request):
    try:
        response = requests.get('http://127.0.0.1:5000/api/rooms')
        if response.status_code == 200:
            rooms = response.json().get('rooms', [])
        else:
            rooms = []
    except Exception as e:
        rooms = []
    return render(request, 'index.html', context={"Room_list": rooms})

def dynamic_template_view(request, template_name):
    return render(request, f'{template_name}')

def aboutus(request):
    return render(request, 'aboutus.html')

def cards_view(request):
    city = request.GET.get('location', 'Chandigarh')
    hostels = [
        {
            'name': 'YWCA Working Women\'s Hostel',
            'image': 'https://im.whatshot.in/img/2021/Sep/hostel-for-working-women-500x500-1630650858.png?wm=1&w=1200&h=630&cc=1',
            'distance': '5km from city centre',
            'discount': '-30%',
            'price': '₹7000',
            'original_price': '₹10000',
            'template': 'template9.html'
        },
        {
            'name': 'Maharana Partap Hostel',
            'image': 'https://www.addressguru.in/images/611876091.webp',
            'distance': '7km from city centre',
            'discount': '-25%',
            'price': '₹6000',
            'original_price': '₹8000',
            'template': 'template10.html'
        },
        {
            'name': 'Mehr Chand Mahajan',
            'image': 'https://content.jdmagicbox.com/comp/chandigarh/h1/0172px172.x172.181113203313.j7h1/catalogue/mehar-chand-mahajan-chandigarh-hostel-for-boy-students-685q4sqemu.jpg',
            'distance': '6km from city centre',
            'discount': '-28%',
            'price': '₹6500',
            'original_price': '₹9000',
            'template': 'template11.html'
        },
        {
            'name': 'Touring Officers Hostel',
            'image': 'https://content.jdmagicbox.com/comp/chandigarh/t7/0172px172.x172.170907025821.u2t7/catalogue/touring-officers-hostel-chandigarh-sector-26-chandigarh-hostels-df5age97bu.jpg',
            'distance': '9km from city centre',
            'discount': '-35%',
            'price': '₹5200',
            'original_price': '₹8000',
            'template': 'template12.html'
        },
        {
            'name': 'Youth Hostel',
            'image': 'https://media-cdn.tripadvisor.com/media/photo-s/07/23/ce/49/dormitory.jpg',
            'distance': '10km from city centre',
            'discount': '-38%',
            'price': '₹5600',
            'original_price': '₹9000',
            'template': 'template13.html'
        },
        {
            'name': 'Kumar PG & Hostel',
            'image': 'https://content3.jdmagicbox.com/comp/chandigarh/q2/0172px172.x172.240206173032.v5q2/catalogue/tg9tyuqn5da6l57-re015yyakp.jpg',
            'distance': '8km from city centre',
            'discount': '-33%',
            'price': '₹5000',
            'original_price': '₹7500',
            'template': 'template14.html'
        },
        {
            'name': 'Anagha Home Stay',
            'image': 'https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSr_tZElrsyJXMoDYzD80nohTE5mPC3czbBsA&s',
            'distance': '11km from city centre',
            'discount': '-32%',
            'price': '₹5800',
            'original_price': '₹8500',
            'template': 'template15.html'
        },
        {
            'name': 'Anchorage',
            'image': 'https://cf.bstatic.com/xdata/images/hotel/max1024x768/437825388.jpg?k=ca5b0786d851f30a78bc0086c9c063be0d13de8a4721195a820dc6de112c9acb&o=&hp=1',
            'distance': '7km from city centre',
            'discount': '-32%',
            'price': '₹5800',
            'original_price': '₹8500',
            'template': 'template16.html'
        }
    ]
    import random
    random.shuffle(hostels)
    return render(request, 'cards.html', {
        'city': city,
        'hostels': hostels
    })

def contact(request):
    return render(request, 'contact.html')

def signup_view(request):
    if request.method == 'POST':
        data = {
            "username": request.POST.get('username'),
            "email": request.POST.get('email'),
            "password": request.POST.get('password'),
            "confirm_password": request.POST.get('confirm_password')
        }
        try:
            response = requests.post('http://localhost:5000/api/signup', json=data)
            result = response.json()
            if response.status_code == 201:
                messages.success(request, result.get('message', 'Registration successful.'))
                return redirect('login')
            else:
                messages.error(request, result.get('error', 'Signup failed.'))
        except requests.exceptions.RequestException as e:
            messages.error(request, f"API error: {str(e)}")
    return render(request, 'signup.html')

def login_view(request):
    if request.method == 'POST':
        data = {
            "username": request.POST.get('username'),
            "password": request.POST.get('password'),
            "role": request.POST.get('role')
        }
        try:
            response = requests.post('http://localhost:5000/api/login', json=data)
            result = response.json()
            if response.status_code == 200:
                user, created = User.objects.get_or_create(username=data['username'])
                if created or not user.check_password(data['password']):
                    user.set_password(data['password'])
                    user.save()
                login(request, user)
                messages.success(request, result.get('message', 'Login successful.'))
                return redirect('HMS_app1_view')
            else:
                messages.error(request, result.get('error', 'Login failed.'))
        except requests.exceptions.RequestException as e:
            messages.error(request, f"API error: {str(e)}")
    return render(request, 'login.html')

@login_required
def logout(request):
    logout_auth(request)
    messages.success(request, "You have been logged out successfully.")
    return redirect('HMS_app1_view')

@login_required
def payments(request):
    if request.method == 'POST':
        amount_str = request.POST.get('amount')
        payment_method = request.POST.get('payment_method')
        try:
            amount = float(amount_str)
            if amount <= 0:
                raise ValueError("Amount must be positive.")
        except ValueError:
            messages.error(request, "Invalid amount. Please enter a valid number.")
            return redirect('payments')
        data = {
            'username': request.user.username,
            'amount': amount,
            'payment_method': payment_method,
            'status': 'Success'
        }
        try:
            response = requests.post('http://localhost:5000/api/payments', json=data)
            if response.status_code == 201:
                messages.success(request, "Payment successful!")
                return redirect('payment_success')
            else:
                result = response.json()
                messages.error(request, result.get('error', 'Failed to process payment.'))
        except requests.exceptions.RequestException as e:
            messages.error(request, f"API error: {str(e)}")
    return render(request, 'payments.html')

def payment_success(request):
    return render(request, 'payment_success.html')

@login_required
def admin_dashboard_view(request):
    total_users = User.objects.all().count()
    total_rooms = Room.objects.all().count()
    total_payments = Payment.objects.all().count()
    context = {
        'total_users': total_users,
        'total_rooms': total_rooms,
        'total_payments': total_payments,
    }
    return render(request, 'admin_dashboard.html', context)

@login_required
def manage_users_view(request):
    try:
        current_user = request.user
        data = {
            'username': current_user.username,
            'password': current_user.password,
            'role': 'admin'
        }
        response = requests.post('http://localhost:5000/api/users', json=data)
        if response.status_code == 200:
            try:
                users = response.json()
                if isinstance(users, list):
                    if not users:
                        print.info(request, "No users found in the system.")
                    return render(request, 'manageUsers.html', {'users': users})
                else:
                    print.error(request, "Unexpected data format from the API.")
            except ValueError as e:
                print.error(request, "Error parsing API response.")
        elif response.status_code == 403:
            print.error(request, "Access denied. Please ensure you have admin privileges.")
        else:
            print.error(request, f"Failed to fetch users from the API. Status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print.error(request, f"API error: {str(e)}")
    return render(request, 'manageUsers.html', {'users': []})

@login_required
def delete_user_view(request, user_id):
    data = {
        'user_id': user_id
    }
    response = requests.delete('http://localhost:5000/api/delete_user', json=data)
    return redirect('manage_users')

@login_required
def manage_rooms_view(request):
    try:
        response = requests.get('http://127.0.0.1:5000/api/rooms')
        if response.status_code == 200:
            rooms = response.json().get('rooms', [])
        else:
            rooms = []
    except Exception as e:
        rooms = []
    return render(request, 'manage_rooms.html', context={"Room_list": rooms})

@login_required
def delete_room_view(request, room_id):
    try:
        response = requests.delete(f'http://localhost:5000/api/delete_rooms/{room_id}')
        if response.status_code == 200:
            messages.success(request, "Room deleted successfully.")
        else:
            messages.error(request, "Failed to delete room. Please try again.")
    except requests.exceptions.RequestException as e:
        messages.error(request, f"API error: {str(e)}")
    return redirect('manage_rooms')

@login_required
def edit_room_view(request, room_id):
    try:
        response = requests.get(f'http://localhost:5000/api/edit_rooms/{room_id}')
        if response.status_code == 200:
            room = response.json()
        else:
            messages.error(request, "Failed to fetch room details.")
            return redirect('manage_rooms')
    except requests.exceptions.RequestException as e:
        messages.error(request, f"API error: {str(e)}")
        return redirect('manage_rooms')
    if request.method == 'POST':
        hostel_name = request.POST.get('hostel_name')
        rating = request.POST.get('rating')
        city = request.POST.get('city')
        image_file = request.FILES.get('image')
        if not all([hostel_name, rating, city]):
            messages.error(request, "All fields are required.")
            return redirect('edit_room_view', room_id=room_id)
        try:
            rating = float(rating)
        except ValueError:
            messages.error(request, "Invalid rating.")
            return redirect('edit_room_view', room_id=room_id)
        if image_file:
            image_dir = os.path.join(settings.MEDIA_ROOT, 'images')
            os.makedirs(image_dir, exist_ok=True)
            image_name = image_file.name
            image_path = os.path.join(image_dir, image_name)
            with open(image_path, 'wb') as f:
                for chunk in image_file.chunks():
                    f.write(chunk)
        else:
            image_name = room.get('image')
        data = {
            'hostel_name': hostel_name,
            'rating': str(rating),
            'city': city,
            'image': image_name,
        }
        try:
            response = requests.put(
                f'http://localhost:5000/api/edit_rooms/{room_id}',
                json=data
            )
            if response.status_code == 200:
                messages.success(request, "Room updated successfully!")
                return redirect('manage_rooms')
            else:
                result = response.json()
                messages.error(request, result.get('error', 'Failed to update room.'))
                return redirect('edit_room_view', room_id=room_id)
        except requests.exceptions.RequestException as e:
            messages.error(request, f"API request failed: {e}")
            return redirect('edit_room_view', room_id=room_id)
    return render(request, 'editroom.html', {'room': room})

@login_required
def add_rooms_view(request):
    if request.method == 'POST':
        hostel_name = request.POST.get('hostel_name')
        rating = request.POST.get('rating')
        city = request.POST.get('city')
        image_file = request.FILES.get('image_name')
        if image_file:
            image_dir = os.path.join(settings.MEDIA_ROOT, 'images')
            if not os.path.exists(image_dir):
                os.makedirs(image_dir)
            image_name = image_file.name
            image_path = os.path.join(image_dir, image_name)
            with open(image_path, 'wb') as f:
                for chunk in image_file.chunks():
                    f.write(chunk)
        else:
            image_name = None
        if not all([hostel_name, rating, city, image_name]):
            return HttpResponseBadRequest("Missing required fields")
        data = {
            'hostel_name': hostel_name,
            'rating': rating,
            'city': city,
            'image_name': image_name
        }
        response = requests.post(
            'http://localhost:5000/api/add_rooms',
            headers={'Content-Type': 'application/json'},
            data=json.dumps(data)
        )
        if response.status_code == 201:
            return redirect('manage_rooms')
        else:
            return HttpResponseBadRequest("Room creation failed in Flask API")
    return render(request, 'add_rooms.html')

@login_required
def manage_payments_view(request):
    try:
        response = requests.get('http://127.0.0.1:5000/api/payments')
        if response.status_code == 200:
            payments = response.json()
        else:
            payments = []
    except Exception as e:
        payments = []
    return render(request, 'manage_payments.html', {"items": payments})

def profile_view(request):
    user = User.objects.all()
    return render(request, 'manageUsers/user_list.html', {'user': user})
