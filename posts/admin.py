from django.contrib import admin

from .models import Post


@admin.register(Post)
class PostAdmin(admin.ModelAdmin):
    list_display = ['title', 'category', 'creator', 'create_at']
    list_filter = ['category', 'create_at']
    search_fields = ['title', 'content']