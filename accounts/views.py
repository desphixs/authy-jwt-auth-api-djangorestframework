from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import RegisterSerializer


# RegisterAPIView handles incoming HTTP POST requests to sign up new users.
# It inherits from DRF's APIView.
# Think of APIView as a specialized security office terminal that is configured 
# to handle specific, manual HTTP actions (like GET, POST, PUT, DELETE).
class RegisterAPIView(APIView):
    
    # We define the POST method to handle user registration data submission.
    # When a visitor fills out the registration form and clicks "Submit",
    # their browser sends a POST request containing JSON data to this endpoint.
    def post(self, request):
        # We instantiate our RegisterSerializer by feeding it the raw request data.
        # Think of this like taking the raw details the user typed on their screen (request.data)
        # and sliding it under the window to our Customs Officer (the serializer).
        serializer = RegisterSerializer(data=request.data)
        
        # We run the customs check!
        # 'is_valid(raise_exception=True)' scans the input fields.
        # It checks if the email is a valid email pattern, if the display nickname is filled out,
        # and if the password is at least 6 characters.
        # If any validation check fails, 'raise_exception=True' automatically stops execution
        # and returns a clear, secure HTTP 400 Bad Request error to the caller.
        serializer.is_valid(raise_exception=True)
        
        # If validation succeeds, we save the user to our SQLite database filing cabinet.
        # serializer.save() triggers our serializer's create() method under the hood,
        # which securely hashes the password and generates the user record in SQLite!
        user = serializer.save()
        
        # We generate a brand-new master security pass (Refresh Token) for this new user.
        # 'RefreshToken.for_user(user)' is SimpleJWT's automatic keycard printer.
        # It generates a unique Refresh Token bound to this user's identity.
        refresh = RefreshToken.for_user(user)
        
        # We compile a success dictionary containing the user's details and active passes.
        # We include the standard user profile card details, the Access pass, and the Refresh pass.
        response_data = {
            # Basic user profile details so the frontend app knows who they are
            'user': {
                'id': user.id,
                'email': user.email,
                'username': user.username,
            },
            # Access Token represents the visitor badge.
            # We convert the access token object to a clean string format!
            'access': str(refresh.access_token),
            # Refresh Token represents the master pass.
            # We convert the refresh token object to a clean string format!
            'refresh': str(refresh),
        }
        
        # We return the response dictionary with an HTTP 201 Created status.
        # This tells the client: "Success! Your account is created, and you are logged in!"
        return Response(response_data, status=status.HTTP_201_CREATED)
