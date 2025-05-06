from django.db import models
from django.contrib.auth.models import User

# Create your models here.

class Room(models.Model):
    id=models.AutoField(primary_key=True)
    hostel_name=models.CharField(max_length=150)
    rating=models.DecimalField(max_digits=3,decimal_places=2)
    city=models.CharField(max_length=150)
    image=models.ImageField(upload_to='room_images/',blank=True,null=True)

    def __str__(self):
        return f"{self.hostel_name}"
    
class Payment(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    amount = models.FloatField()
    payment_method = models.CharField(max_length=50)
    transaction_id = models.CharField(max_length=50)
    status = models.CharField(max_length=50)
    date = models.DateTimeField(auto_now_add=True)


    def __str__(self):
        return f"{self.user.username} - {self.transaction_id}"


class User(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=128)
    role = models.CharField(max_length=20, default='user')

    def __str__(self):
        return f"{self.user.username} - {self.email} - {self.password}"