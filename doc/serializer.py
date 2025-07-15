from rest_framework import serializers
from django.contrib.auth.models import User
import re


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True, required=True, style={"input_type": "password"}
    )

    class Meta:
        model = User
        fields = ["username", "email", "password"]

    def validate_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError(
                "Password must be at least 8 characters long."
            )
        if not re.search(r"[A-Z]", value):
            raise serializers.ValidationError(
                "Password must contain at least one uppercase letter."
            )
        if not re.search(r"[a-z]", value):
            raise serializers.ValidationError(
                "Password must contain at least one lowercase letter."
            )
        if not re.search(r"\d", value):
            raise serializers.ValidationError(
                "Password must contain at least one digit."
            )
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", value):
            raise serializers.ValidationError(
                "Password must contain at least one special character."
            )
        return value

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username is already taken.")
        return value

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email is already registered.")
        return value


    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data["username"],
            email=validated_data.get("email"),
            password=validated_data["password"],
            is_active=False,
        )
        return user


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["username", "email"]


class DemoRequestSerializer(serializers.Serializer):
    name = serializers.CharField()
    title = serializers.CharField()
    emailAddress = serializers.EmailField()
    mobileNumber = serializers.CharField()
    country = serializers.CharField()
    city = serializers.CharField()
    region = serializers.CharField()
    requested_solution = serializers.CharField()
    companyName = serializers.CharField()
    number_of_users = serializers.IntegerField()
    industry = serializers.CharField()
    whereAboutUs = serializers.CharField(required=False, default="None", allow_blank=True)


class ContactUsSerializer(serializers.Serializer):
    name = serializers.CharField()
    emailAddress = serializers.EmailField()
    mobileNumber = serializers.CharField()
    message = serializers.CharField()
