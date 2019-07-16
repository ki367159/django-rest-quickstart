from django.db import models
from posts.models import Post
from users.models import User

class Comment(models.Model):
    post = models.ForeignKey(Post, on_delete=models.CASCADE)
    content = models.TextField(max_length=3000)
    creator = models.ForeignKey(User, on_delete=models.PROTECT)
    create_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.content