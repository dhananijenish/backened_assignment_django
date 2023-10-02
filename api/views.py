from rest_framework import permissions
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User, Post
from .serializers import CustomTokenRefreshSerializer, UserLoginSerializer, UserSerializer, PostSerializer
from rest_framework import status, views
from rest_framework_simplejwt.views import TokenRefreshView
from django.contrib.auth import authenticate, login
from django.shortcuts import get_object_or_404


class UserRegistrationView(views.APIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        refresh = RefreshToken.for_user(user)

        return Response({
            'user_id': user.id,
            'email': user.email,
            'access': str(refresh.access_token),
            'refresh': str(refresh),
        }, status=status.HTTP_201_CREATED)


class UserLoginView(views.APIView):
    serializer_class = UserLoginSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']

        user = authenticate(request, email=email, password=password)

        if user is not None:
            login(request, user)
            user.save(update_fields=['last_login'])
            refresh = RefreshToken.for_user(user)
            return Response({
                "email": user.email,
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }, status=status.HTTP_200_OK)
        else:
            return Response({'detail': 'Unable to log in with provided credentials.'}, status=status.HTTP_400_BAD_REQUEST)


class TokenRefreshCustomView(TokenRefreshView):
    serializer_class = CustomTokenRefreshSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        response.data['access'] = str(response.data['access'])
        return response


class PostView(views.APIView):
    queryset = Post.objects.all()
    serializer_class = PostSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        posts = self.queryset.filter(user=request.user)
        serializer = self.serializer_class(posts, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        request.data['user'] = request.user.id
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        if request.user.is_authenticated:
            serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class PostDetailView(views.APIView):
    queryset = Post.objects.all()
    serializer_class = PostSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, id, *args, **kwargs):
        post = self.queryset.filter(pk=id, user=request.user).first()
        if not post:
            return Response({"detail": "Post not found."}, status=status.HTTP_400_BAD_REQUEST)
        serializer = self.serializer_class(post, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request, id, *args, **kwargs):
        post = self.queryset.filter(pk=id, user=request.user).first()
        if not post:
            return Response({"detail": "Post not found."}, status=status.HTTP_400_BAD_REQUEST)
        serializer = self.serializer_class(
            post, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, id, *args, **kwargs):
        post = self.queryset.filter(pk=id, user=request.user).first()
        if not post:
            return Response({"detail": "Post not found."}, status=status.HTTP_400_BAD_REQUEST)
        post.delete()
        return Response({"detail": "Post successfully deleted."}, status=status.HTTP_204_NO_CONTENT)
