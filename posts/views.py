from rest_framework.viewsets import ModelViewSet
from rest_framework.permissions import IsAuthenticatedOrReadOnly
from core.permissions import IsCreatorOrReadOnly
from .models import Post
from .serializers import PostSerializer, PostCommentSerializer

class PostViewSet(ModelViewSet):
    queryset = Post.objects.all()
    serializer_class = PostSerializer
    permission_classes = [IsAuthenticatedOrReadOnly, IsCreatorOrReadOnly]

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return PostCommentSerializer

        return super().get_serializer_class()

    def perform_create(self, serializer):
        serializer.save(creator=self.request.user)