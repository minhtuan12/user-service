from __future__ import unicode_literals
from django.db import models

USER_ROLE = {
    'ADMIN': 0,
    'USER': 1,
    'SUPER_ADMIN': 2
}


class User(models.Model):
    first_name = models.CharField(max_length = 50)
    last_name = models.CharField(max_length = 50)
    username = models.CharField(max_length = 50)
    email = models.CharField(max_length = 50)
    mobile = models.CharField(max_length = 10)
    password = models.CharField(max_length = 200)
    address = models.CharField(max_length = 200, blank = True, null = True)
    role = models.PositiveIntegerField(default = USER_ROLE['USER'])
    created_at = models.DateTimeField(auto_now_add = True)
    deleted = models.BooleanField(default = False)

    def __str__(self):
        return '%s %s %s %s %s %s' % (self.first_name, self.last_name, self.
                                      email, self.mobile, self.password, self.address)
