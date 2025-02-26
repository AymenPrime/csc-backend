from django.contrib.auth.backends import BaseBackend
from .models import User

class CustomUserBackend(BaseBackend):
    def authenticate(self, request, name=None, password=None, **kwargs):
        try:
            user = User.objects.get(name=name)
            if user.check_password(password):
                return user
        except User.DoesNotExist:
            return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None