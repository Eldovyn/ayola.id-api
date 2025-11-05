from flask import Blueprint, request
from ..controllers import (
    LoginController,
    RegisterController,
    ResetPasswordController,
)
from ..utils import jwt_required

auth_router = Blueprint("auth_router", __name__)
login_controller = LoginController()
register_controller = RegisterController()
reset_password_controller = ResetPasswordController()


@auth_router.post("/login")
async def user_login():
    data = request.json
    timestamp = request.timestamp
    email = data.get("email", "")
    password = data.get("password", "")
    provider = data.get("provider", "")
    token = data.get("token", "")
    return await login_controller.user_login(
        provider, token, email, password, timestamp
    )


@auth_router.post("/logout")
@jwt_required()
async def user_logout():
    user = request.user
    token = request.token
    return await login_controller.user_logout(user, token)


@auth_router.post("/reset-password/request")
async def send_reset_password_email():
    data = request.json
    timestamp = request.timestamp
    email = data.get("email", "")
    return await reset_password_controller.send_reset_password_email(email, timestamp)


@auth_router.get("/reset-password/password-changed/<string:token>")
async def get_user_reset_password_verification(token):
    timestamp = request.timestamp
    return await reset_password_controller.get_user_reset_password_verification(
        token, timestamp
    )


@auth_router.post("/reset-password/password-changed/<string:token>")
async def user_reset_password_verification(token):
    timestamp = request.timestamp
    json = request.json
    confirm_password = json.get("confirm_password", "")
    password = json.get("password", "")
    return await reset_password_controller.user_reset_password_verification(
        token, password, confirm_password, timestamp
    )


@auth_router.post("/register")
async def user_register():
    data = request.json
    timestamp = request.timestamp
    username = data.get("username", "")
    email = data.get("email", "")
    password = data.get("password", "")
    confirm_password = data.get("confirm_password", "")
    provider = data.get("provider", "")
    token = data.get("token", "")
    return await register_controller.user_register(
        provider,
        token,
        username,
        email,
        password,
        confirm_password,
        timestamp,
    )
