from django.urls import path
from .views import RegisterView, LoginView, LeaderboardView, UpdatePointsView, DeleteUserView, get_csrf_token

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('leaderboard/', LeaderboardView.as_view(), name='leaderboard'),
    path('update-points/<int:user_id>/', UpdatePointsView.as_view(), name='update-points'),
    path('delete-user/<int:user_id>/', DeleteUserView.as_view(), name='delete-user'),  # Add this line
    path('csrf/', get_csrf_token, name='csrf'),
    path('update-profile-picture/<int:user_id>/', UpdateProfilePictureView.as_view(), name='update-profile-picture'),
]