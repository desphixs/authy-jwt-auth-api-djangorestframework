from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
# We import IsAuthenticated so that only logged-in users with valid access tokens can access logout
from rest_framework.permissions import IsAuthenticated
# We import RegisterSerializer to handle signups and LoginSerializer to handle credentials checking
from .serializers import RegisterSerializer, LoginSerializer


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


# LoginAPIView handles incoming HTTP POST requests to verify credentials and log in.
# It inherits from DRF's APIView.
# Think of APIView as a specialized security office desk configured to handle custom actions.
class LoginAPIView(APIView):
    
    # We define the POST method to receive and process user credentials.
    def post(self, request):
        # We instantiate our LoginSerializer with the incoming request details.
        # This sends email and password straight to our data validator (the customs officer).
        serializer = LoginSerializer(data=request.data)
        
        # We run our bouncer and validation steps!
        # If credentials fail (e.g. wrong password), .is_valid() catches the ValidationError,
        # stops execution immediately, and returns an HTTP 400 Bad Request to the user.
        serializer.is_valid(raise_exception=True)
        
        # Once validated, we retrieve our verified 'user' instance from the serializer's parsed data attributes.
        # Remember, our LoginSerializer validator securely stashed the User object inside attrs['user']!
        user = serializer.validated_data['user']
        
        # We print a brand-new master security pass (Refresh Token) for this returning user.
        # 'RefreshToken.for_user(user)' automatically issues access and refresh keycards.
        refresh = RefreshToken.for_user(user)
        
        # We compile a success dictionary containing the user's details and fresh keycards.
        response_data = {
            'user': {
                'id': user.id,
                'email': user.email,
                'username': user.username,
            },
            # Access Token represents the visitor badge
            'access': str(refresh.access_token),
            # Refresh Token represents the master pass
            'refresh': str(refresh),
        }
        
        # We return the response payload with an HTTP 200 OK status to let the client know
        # they have successfully logged in!
        return Response(response_data, status=status.HTTP_200_OK)


# LogoutAPIView handles incoming HTTP POST requests to log out users by blacklisting their refresh tokens.
# It inherits from DRF's APIView.
# Think of APIView as a specialized security office desk configured to handle custom actions.
class LogoutAPIView(APIView):
    # We require the user to be fully authenticated to access this logout desk!
    # 'permission_classes = [IsAuthenticated]' acts like a security bouncer standing in front 
    # of the desk: if a visitor does not have a valid, active Access Token in their request header,
    # the guard blocks them immediately with an HTTP 401 Unauthorized warning.
    permission_classes = [IsAuthenticated]

    # We define the POST method to process the logout request.
    def post(self, request):
        try:
            # We pull the 'refresh' token string out of the incoming request body data.
            # This is the master card they want to destroy.
            refresh_token = request.data.get('refresh')

            # If the visitor did not provide a refresh token inside the payload, we throw an error.
            if not refresh_token:
                return Response(
                    {"detail": "Refresh token is required to log out."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # We convert the raw string token into a SimpleJWT 'RefreshToken' object.
            # This parses the token structure and checks if it is cryptographically signed.
            token = RefreshToken(refresh_token)

            # We permanently blacklist the token!
            # The '.blacklist()' method takes the parsed refresh token, extracts its unique signature (jti),
            # and writes it permanently into our SQLite database blacklist ledger tables.
            # Moving forward, whenever this refresh token is presented to mint a new access token,
            # the system checks the blacklist ledger, finds the match, and immediately rejects it!
            token.blacklist()

            # We return a successful response to let the client know logout was fully successful.
            return Response(
                {"detail": "Successfully logged out. Refresh token has been blacklisted."},
                status=status.HTTP_200_OK
            )

        except Exception as e:
            # If the token is invalid, expired, or already blacklisted, SimpleJWT throws an exception.
            # We catch it and return a clear HTTP 400 Bad Request error.
            return Response(
                {"detail": "Invalid or already blacklisted refresh token."},
                status=status.HTTP_400_BAD_REQUEST
            )
