import time
from rest_framework.exceptions import NotFound, PermissionDenied
from django.contrib.auth import authenticate
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from rest_framework.generics import get_object_or_404
from rest_framework.viewsets import ModelViewSet
from rest_framework.exceptions import AuthenticationFailed, NotFound
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.authtoken.models import Token

from .permissions import IsCurrentUser
from .models import User
from .serializers import UserSerializer, LoginSerializer, PasswordSetSerializer, PasswordResetSerializers


class UserViewSet(ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAdminUser]

    def get_serializer_class(self):
        return {
            'login': LoginSerializer,
            'set_password': PasswordSetSerializer,
            'reset_password': PasswordResetSerializers
        }.get(self.action, super().get_serializer_class())

    def perform_create(self, serializer):
        user = serializer.save()
        user.send_password_set_email()

    def get_permissions(self):
        if self.action == 'create':
            return []

        if self.action in ['update', 'partial_update']:
            return [IsCurrentUser()]

        return super().get_permissions()

    @action(['POST'], False, permission_classes=[])
    def login(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = authenticate(**serializer.data)
        if user is None:
            raise AuthenticationFailed()

        token, _ = Token.objects.get_or_create(user=user)
        return Response({
            'token': token.key,
            'users': UserSerializer(user).data,
        })

    @action(['POST'],
            False,
            'password-set/(?P<uidb64>[^/.]+)/(?P<token>[^/.]+)',
            permission_classes=[],)
    def set_password(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
        except ValueError:
            raise NotFound()

        user = get_object_or_404(User, pk=uid)
        request.user = user

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        if not default_token_generator.check_token(user, token):
            raise PermissionDenied('Token check fail.')

        user.set_password(serializer.data['password'])
        user.save()

        return Response({
            'success': True,
        })

    @action(['POST'], False, permission_classes=[])
    def password_reset(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = User.objects.filter(email=serializer.data['email']).first()
        if not user:
            time.sleep(3)
        else:
            user.send_password_set_email()

        return Response({
            'success': True,
        })

    @action(['GET'], False, permission_classes=[IsAuthenticated])
    def me(self, request):
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)