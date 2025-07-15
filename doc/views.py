import re 

from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.conf import settings
from django.urls import reverse
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.core.mail import send_mail

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

from .serializer import (
    RegisterSerializer,
    UserSerializer,
    DemoRequestSerializer,
    ContactUsSerializer,
)


def send_activation_email(user, request):
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)

    activation_link = f"http://localhost:3000/Activate?code={token}&id={uid}"

    html_message = render_to_string(
        "doc/activation_email.html",
        {
            "email": user.email,
            "activation_link": activation_link,
            "logo_url": "https://7b979163062c.ngrok-free.app/static/doc/logo.jpeg",
        },
    )

    plain_message = strip_tags(html_message)

    subject = "Activate Your Account"
    from_email = settings.DEFAULT_FROM_EMAIL
    to_email = [user.email]

    msg = EmailMultiAlternatives(subject, plain_message, from_email, to_email)
    msg.attach_alternative(html_message, "text/html")
    msg.send()


@api_view(["POST"])
def activate_account(request):
    uidb64 = request.data.get("uidb64")
    token = request.data.get("token")

    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        return Response({"message": "Invalid activation link."}, status=400)

    if default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        return Response({"message": "Account activated successfully!"}, status=200)
    else:
        return Response(
            {"message": "Activation link is invalid or expired."}, status=400
        )


@api_view(["POST"])
def resend_activation_email(request):
    email = request.data.get("email")

    if not email:
        return Response(
            {"message": "Email is required."}, status=status.HTTP_400_BAD_REQUEST
        )

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response(
            {"message": "If the email exists, a verification email will be resent."},
            status=status.HTTP_200_OK,
        )

    if user.is_active:
        return Response(
            {"message": "This account is already activated."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    send_activation_email(user, request)

    return Response(
        {"message": "If the email exists, a verification email will be resent."},
        status=status.HTTP_200_OK,
    )


@api_view(["POST"])
def forgot_password(request):
    email = request.data.get("email")

    if not email:
        return Response(
            {"message": "Email is required."}, status=status.HTTP_400_BAD_REQUEST
        )

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response(
            {"message": "We couldn't find an account with that email."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)

    reset_link = f"http://localhost:3000/Reset-Password?code={token}&id={uid}"

    html_message = render_to_string(
        "doc/forgot_password.html",
        {
            "email": user.email,
            "reset_link": reset_link,
            "logo_url": "https://7b979163062c.ngrok-free.app/static/doc/logo.jpeg",
        },
    )

    plain_message = strip_tags(html_message)

    subject = "Reset Your Password"
    from_email = settings.DEFAULT_FROM_EMAIL
    to_email = [user.email]

    msg = EmailMultiAlternatives(subject, plain_message, from_email, to_email)
    msg.attach_alternative(html_message, "text/html")
    msg.send()

    return Response(
        {"message": "Password reset link sent if email exists."},
        status=status.HTTP_200_OK,
    )


@api_view(["POST"])
def reset_password(request):
    uidb64 = request.data.get("uidb64")
    token = request.data.get("token")

    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        return Response({"message": "Invalid link."}, status=status.HTTP_400_BAD_REQUEST)

    if not default_token_generator.check_token(user, token):
        return Response(
            {"message": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST
        )

    password = request.data.get("password")

    if not password:
        return Response(
            {"message": "Password field is required."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    if len(password) < 8:
        return Response(
            {"message": "Password must be at least 8 characters long."},
            status=status.HTTP_400_BAD_REQUEST
        )
    if not re.search(r"[A-Z]", password):
        return Response(
            {"message": "Password must contain at least one uppercase letter."},
            status=status.HTTP_400_BAD_REQUEST
        )
    if not re.search(r"[a-z]", password):
        return Response(
            {"message": "Password must contain at least one lowercase letter."},
            status=status.HTTP_400_BAD_REQUEST
        )
    if not re.search(r"\d", password):
        return Response(
            {"message": "Password must contain at least one digit."},
            status=status.HTTP_400_BAD_REQUEST
        )
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return Response(
            {"message": "Password must contain at least one special character."},
            status=status.HTTP_400_BAD_REQUEST
        )

    user.set_password(password)
    user.save()

    return Response(
        {"message": "Password has been reset successfully."}, status=status.HTTP_200_OK
    )


@api_view(["POST"])
def register(request):
    serializer = RegisterSerializer(data=request.data)

    if serializer.is_valid():
        user = serializer.save()
        send_activation_email(user, request)

        return Response(
            {
                "message": "User registered successfully!",
            },
            status=status.HTTP_201_CREATED,
        )

    errors = serializer.errors
    first_field = next(iter(errors))
    first_error = {"message": errors[first_field][0]}

    return Response(first_error, status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
def login(request):
    email = request.data.get("email")
    password = request.data.get("password")

    if not email or not password:
        return Response(
            {"message": "Email and password are required."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    user = authenticate(email=email, password=password)

    if user is not None:
        if not user.is_active:
            return Response(
                {"message": "Account is not activated. Please verify your email."},
                status=status.HTTP_403_FORBIDDEN,
            )

        refresh = RefreshToken.for_user(user)
        access = refresh.access_token
        response = Response({"message": "Login successful!", 
                            'refresh': str(refresh),
                            'access': str(access),},
                             status=status.HTTP_200_OK)
        
        return response
        

    return Response(
        {"message": "Invalid email or password."
        }, status=status.HTTP_401_UNAUTHORIZED
    )


@api_view(["POST"])
def logout(request):
    refresh_token = request.data.get("refresh")
    
    if not refresh_token:
        return Response({"error": f"No refresh token found."}, status=400)

    try:
        token = RefreshToken(refresh_token)
        token.blacklist()
    except TokenError:
        return Response(
            {"error": "Invalid or expired refresh token."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    response = Response({"message": f"Logged out successfully."}, status=status.HTTP_205_RESET_CONTENT)

    return response


@api_view(["GET"])
def me(request):
    user = request.user
    serializer = UserSerializer(user)
    return Response(serializer.data)


@api_view(["POST"])
def request_demo(request):
    serializer = DemoRequestSerializer(data=request.data)

    if serializer.is_valid():
        data = serializer.validated_data

        subject = "New Demo Request"
        message = f"""
        A new demo has been requested with the following details:

        Name: {data['name']}
        Title: {data['title']}
        Email: {data['emailAddress']}
        Mobile: {data['mobileNumber']}
        Country: {data['country']}
        City: {data['city']}
        Region: {data['region']}
        Requested Solution: {data['requested_solution']}
        Company: {data['companyName']}
        Users: {data['number_of_users']}
        Industry: {data['industry']}
        Heard About Us: {data['whereAboutUs']}
        """

        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            ["mohamedalshazly162@gmail.com"],
        )

        return Response(
            {"message": "Demo request submitted successfully."},
            status=status.HTTP_200_OK,
        )

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
def contact_us(request):
    serializer = ContactUsSerializer(data=request.data)

    if serializer.is_valid():
        data = serializer.validated_data

        subject = "New Contact Us Message"
        message = f"""
        You received a new contact form submission:

        Name: {data['name']}
        Email: {data['emailAddress']}
        Mobile: {data['mobileNumber']}
        Message: {data['message']}
        """

        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            ["mohamedalshazly162@gmail.com"],
        )

        return Response(
            {"message": "Your message was sent successfully!"},
            status=status.HTTP_200_OK,
        )

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
