from django import urls
from django.urls import path
from . import views

urlpatterns = [
    path('', views.HMS_app1_view, name='HMS_app1_view'),
    path('aboutus/', views.aboutus, name='aboutus'),
    path('contact/', views.contact, name='contact'),
    path('login/', views.login_view, name='login'),
    path('signup/', views.signup_view, name='signup'),
    path('logout/', views.logout, name='logout'),
    path('payments/', views.payments, name='payments'),
    path('dashboard/', views.admin_dashboard_view, name='a_dash'),
    path('manage_users/', views.manage_users_view, name='manage_users'),
    path('users/<int:user_id>/delete/',views.delete_user_view, name='delete_user'),
    path('manage_rooms/', views.manage_rooms_view, name='manage_rooms'),
    path('rooms/<int:room_id>/delete/', views.delete_room_view, name='delete_room'),
    path('rooms/<int:room_id>/edit/', views.edit_room_view, name='edit_room'),
    path('manage_payments/', views.manage_payments_view, name='manage_payments'),
    path('add_rooms/', views.add_rooms_view, name='add_rooms'),
    path('paymentsuccess/', views.payment_success, name='payment_success'),
    path('cards/',views.cards_view,name='cards'),
    path('<str:template_name>/', views.dynamic_template_view, name='dynamic_template'),
    path('cards/<str:template_name>/', views.dynamic_template_view, name='dynamic_template'),
]