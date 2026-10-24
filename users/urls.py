from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register_user),
    path('login/', views.CustomTokenObtainPairView.as_view()),
    path('logout/', views.logout_user),
    path('profile/', views.user_profile),
]