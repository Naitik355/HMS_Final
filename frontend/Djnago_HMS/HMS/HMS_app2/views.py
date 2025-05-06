from django.shortcuts import render,redirect
from django.contrib import messages

# Create your views here.
def HMS_app2_view(request):
    return render (request,'ghar.html')

def breakfast_view(request):
    return render (request,'breakfast.html')

def lunch_view(request):
    return render (request,'lunch.html')

def dinner_view(request):
    return render (request,'dinner.html')

def slotbooking_view(request):
    return render (request,'slotbooking.html')

def aboutUs_view(request):
    return render (request,'aboutUs.html')

def contactUs_view(request):
    return render (request,'contactUs.html')

def payment_view(request):
    messages.success(request,'Payment was successful!')
    return render (request,'payment.html')

def order_view(request):
    return render (request,'order.html')