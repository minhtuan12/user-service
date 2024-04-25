from django.core.management.base import BaseCommand
from model.models import User, USER_ROLE
from helpers import hash_password


class Command(BaseCommand):
    help = 'Seeds the database.'

    def handle(self, *args, **options):
        User.objects.all().delete()
        User.objects.create(first_name = 'Super', last_name = 'Admin', username = 'super-admin',
                            role = USER_ROLE['SUPER_ADMIN'], password = hash_password('Superadmin@123'))

        self.stdout.write(self.style.SUCCESS('Successfully seeded super admin'))
