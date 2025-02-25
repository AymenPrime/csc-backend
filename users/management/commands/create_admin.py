from django.core.management.base import BaseCommand
from django.contrib.auth.models import User

class Command(BaseCommand):
    help = 'Creates the default admin user'

    def handle(self, *args, **kwargs):
        if not User.objects.filter(username='aymenox').exists():
            User.objects.create_superuser(
                username='aymenox',
                password='aymenox147',
                email='aymenox@example.com'
            )
            self.stdout.write(self.style.SUCCESS('Default admin user created successfully!'))
        else:
            self.stdout.write(self.style.WARNING('Default admin user already exists.'))