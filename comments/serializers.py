from rest_framework import serializers
from .models import Comment

class CommentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Comment
        exclude = ['creator']
        read_only_fields = ['creat_at']
