from django.urls import path
from .views import TokenRefreshCustomView, UserRegistrationView, UserLoginView, PostView, PostDetailView

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('token/refresh/', TokenRefreshCustomView.as_view(), name='token-refresh'),
    path('posts/', PostView.as_view(), name='post'),
    path('posts/<int:id>', PostDetailView.as_view(), name='post-details'),
]
