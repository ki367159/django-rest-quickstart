from django.db import models
from categories.models import Category
from users.models import User

class Post(models.Model):
    title = models.CharField(max_length=255)
    content = models.TextField(max_length=3000)
    category = models.ForeignKey(Category, on_delete=models.PROTECT)
    creator = models.ForeignKey(User, on_delete=models.PROTECT)
    create_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title
