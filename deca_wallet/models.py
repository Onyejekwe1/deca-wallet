import shortuuid
import uuid
from django.db import models
from django.utils import timezone as t
from django.contrib.auth.models import AbstractUser


# Create your models here.
class User(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    first_name = models.CharField(max_length=250, null=False)
    last_name = models.CharField(max_length=250, null=False)
    email = models.CharField(max_length=100, null=False, unique=True)
    username = models.CharField(max_length=100, null=False, unique=True)
    date_joined = models.DateTimeField(auto_now=False, default=t.now)
    date_updated = models.DateTimeField(auto_now=True)
    is_admin = models.BooleanField(default=False)


class Noob(models.Model):
    noob_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.OneToOneField(User, on_delete=models.CASCADE)
    currency_main = models.CharField(max_length=100, null=False)
    date_joined = models.DateTimeField(auto_now=False, default=t.now)
    date_updated = models.DateTimeField(auto_now=True)
    wallet_category = models.CharField(max_length=100, null=False)


class Elite(models.Model):
    elite_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.OneToOneField(User, on_delete=models.CASCADE)
    currency_main = models.CharField(max_length=100, null=False)
    date_joined = models.DateTimeField(auto_now=False, default=t.now)
    date_updated = models.DateTimeField(auto_now=True)
    wallet_category = models.CharField(max_length=100, null=False)


class Wallet(models.Model):
    wallet_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.ForeignKey(User, on_delete=models.CASCADE)
    currency = models.CharField(max_length=100, null=False)
    wallet_balance = models.CharField(max_length=255, null=False)
    date_created = models.DateTimeField(auto_now=False, default=t.now)
    date_updated = models.DateTimeField(auto_now=True)
    main_wallet = models.BooleanField()


class WalletTransaction(models.Model):
    wallet_transaction_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.ForeignKey(User, on_delete=models.CASCADE)
    wallet_id = models.ForeignKey(Wallet, on_delete=models.CASCADE)
    transaction_category = models.CharField(max_length=100, null=False)
    amount = models.CharField(max_length=255, null=False)
    date_created = models.DateTimeField(auto_now=False, default=t.now)
    date_updated = models.DateTimeField(auto_now=True)
    currency = models.CharField(max_length=100, null=False)
    operation_status = models.CharField(max_length=100, null=False)


