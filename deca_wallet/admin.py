from django.contrib import admin
from .models import User, WalletTransaction, Elite, Noob, Wallet


# Register your models here.
admin.site.register(User)
admin.site.register(Noob)
admin.site.register(Elite)
admin.site.register(Wallet)
admin.site.register(WalletTransaction)
