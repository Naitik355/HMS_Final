from django.contrib import admin
from .models import  Room
from .models import Payment
from .models import User

@admin.register(Room)
class RoomAdmin(admin.ModelAdmin):
    list_display = ('hostel_name', 'rating', 'city')  # columns to display
    search_fields = ('hostel_name', 'city')
    list_filter = ('city',)
    ordering = ('hostel_name',)

@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = ('user', 'amount', 'payment_method', 'transaction_id', 'status', 'date')
    search_fields = ('user__username', 'transaction_id')
    list_filter = ('payment_method', 'status')
    date_hierarchy = 'date'


admin.site.register(User)

# Register your models here.
