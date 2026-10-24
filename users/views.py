from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone
from datetime import timedelta
from .models import User
from .serializers import (
    RegisterSerializer,
    CustomTokenObtainPairSerializer,
    UserProfileSerializer
)

@api_view(['POST'])
@permission_classes([AllowAny])
def register_user(request):
    serializer = RegisterSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(
            {"message": "Account created successfully! Please login."},
            status=status.HTTP_201_CREATED
        )
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# ── Login ─────────────────────────────────────────────────────
class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        username = request.data.get('username')

        # Check user exists
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response(
                {"error": "No account found with this username."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # Check lockout
        if user.is_locked():
            remaining = (user.locked_until - timezone.now()).seconds // 60
            return Response(
                {"error": f"Account locked. Try again in {remaining} minutes."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Attempt login
        response = super().post(request, *args, **kwargs)

        if response.status_code == 200:
            # Success
            user.failed_login_attempts = 0
            user.locked_until = None
            user.active_session_token = response.data.get('access')
            user.save()
        else:
            # Failed
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= 5:
                user.locked_until = timezone.now() + timedelta(minutes=15)
                user.failed_login_attempts = 0
                user.save()
                return Response(
                    {"error": "Too many failed attempts. Account locked for 15 minutes."},
                    status=status.HTTP_403_FORBIDDEN
                )
            user.save()
            remaining = 5 - user.failed_login_attempts
            return Response(
                {"error": f"Wrong password. {remaining} attempts remaining."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        return response


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_user(request):
    try:
        refresh_token = request.data.get('refresh')
        token = RefreshToken(refresh_token)
        token.blacklist()
        if request.user.is_authenticated:
            request.user.active_session_token = None
            request.user.save()
        return Response({"message": "Logged out successfully."})
    except Exception:
        return Response(
            {"error": "Invalid token."},
            status=status.HTTP_400_BAD_REQUEST
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_profile(request):
    serializer = UserProfileSerializer(request.user)
    return Response(serializer.data)