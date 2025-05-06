from django import urls
from django.urls import path
from . import views

urlpatterns=[
    path('',views.HMS_app2_view,name='HMS_app2'),
    path('AboutUs/',views.aboutUs_view,name='aboutus'),
    path('contactUs/',views.contactUs_view,name='contactUs'),
    path('BreakFast/',views.breakfast_view,name='breakfast'),
    path('Lunch/',views.lunch_view,name='lunch'),
    path('Dinner/',views.dinner_view,name='dinner'),
    path('SlotBooking/',views.slotbooking_view,name='slotbooking'),
    path('OrderNow/',views.order_view,name='orderNow'),
    path('Payment/',views.payment_view,name='payment_page'),
]