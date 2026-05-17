from django.urls import path
# We import our RegisterAPIView class from our views module
from .views import RegisterAPIView

# urlpatterns defines a list of URL patterns that this specific application handles.
# Think of urlpatterns like a local department directory that maps a visitor's request 
# straight to the correct office room desk!
urlpatterns = [
    # path() defines the specific url pathway and maps it to the view.
    # We map 'register/' to RegisterAPIView.
    # Since RegisterAPIView is a Class-Based View, we must call '.as_view()' 
    # to unpack and convert our view class into a standard callable function.
    path('register/', RegisterAPIView.as_view(), name='register'),
]
