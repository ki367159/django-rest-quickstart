from rest_framework import serializers
from comments.serializers import CommentSerializer
from .models import Post

class PostSerializer(serializers.ModelSerializer):
    class Meta:
        model = Post
        fields = '__all__'
        read_only_fields = ['creator', 'creat_at']

class PostCommentSerializer(serializers.ModelSerializer):
    comments = CommentSerializer(many=True, read_only=True)
    class Meta:
        model = Post
        fields = '__all__'
        read_only_fields = ['creator', 'creat_at']