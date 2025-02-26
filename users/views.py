from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import User
from .serializers import UserSerializer
from django.contrib.auth import authenticate, login
from django.middleware.csrf import get_token
from django.http import JsonResponse
from rest_framework.parsers import MultiPartParser, FormParser

# Pre-generated verification codes
PRE_GENERATED_CODES = [
    'A1B2C3', 'D4E5F6', 'G7H8I9', 'J1K2L3', 'M4N5O6',
    'P7Q8R9', 'S1T2U3', 'V4W5X6', 'Y7Z8A9', 'B1C2D3',
    'E4F5G6', 'H7I8J9', 'K1L2M3', 'N4O5P6', 'Q7R8S9',
    'T1U2V3', 'W4X5Y6', 'Z7A8B9', 'C1D2E3', 'F4G5H6'
]


class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            # Create a new user using the custom User model
            user = User.objects.create_user(
                name=serializer.validated_data['name'],
                password=serializer.validated_data['password'],
                picture=serializer.validated_data.get('picture'),
                verification_code=serializer.validated_data.get('verification_code'),
                points=serializer.validated_data.get('points', 0),
            )
            return Response({'message': 'Registration successful'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    def post(self, request):
        name = request.data.get('name')  # Use 'name' instead of 'username'
        password = request.data.get('password')

        # Authenticate the user using the custom User model
        user = authenticate(request, name=name, password=password)

        if user is not None:
            # Log the user in
            login(request, user)
            return Response({'message': 'Login successful'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

def get_csrf_token(request):
    token = get_token(request)
    return JsonResponse({'csrfToken': token})

class LeaderboardView(APIView):
    def get(self, request):
        # Fetch users sorted by points in descending order
        users = User.objects.exclude(name='cscadmin').order_by('-points')
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)

class UpdatePointsView(APIView):
    def post(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
            points_to_add = int(request.data.get('points', 0))
            user.points += points_to_add  # Add points to the existing points
            user.save()
            serializer = UserSerializer(user)
            return Response(serializer.data)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

class DeleteUserView(APIView):
    def delete(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
            user.delete()
            return Response({'message': 'User deleted successfully'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)


class UpdateProfilePictureView(APIView):
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
            if user.name != request.user.name:
                return Response({'error': 'You can only update your own profile picture'}, status=status.HTTP_403_FORBIDDEN)
            
            picture = request.FILES.get('picture')
            if picture:
                user.picture = picture
                user.save()
                return Response({'message': 'Profile picture updated successfully'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'No picture provided'}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)