from rest_framework import serializers
from comments.serializers import CommentSerializer
from .models import Post

class PostSerializer(serializers.ModelSerializer):
    class Meta:
        model = Post
        exclude = ['creator']
        read_only_fields = ['creat_at']

class PostCommentSerializer(serializers.ModelSerializer):
    comments = CommentSerializer(many=True, read_only=True)
    class Meta:
        model = Post
        exclude = ['creator']
        read_only_fields = ['creat_at']
