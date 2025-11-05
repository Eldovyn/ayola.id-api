from ..databases import UserDatabase
from flask import jsonify, url_for
import requests
from ..utils import (
    AuthJwt,
    Validation,
)
from ..serializers import UserSerializer, TokenSerializer
from ..dataclasses import AccessTokenSchema


class RegisterController:
    def __init__(self):
        self.user_seliazer = UserSerializer()
        self.token_serializer = TokenSerializer()

    async def user_register(
        self,
        provider,
        token,
        username,
        email,
        password,
        confirm_password,
        timestamp,
    ):
        from ..extensions import bcrypt

        access_token = None
        token_web = None

        try:
            errors = {}
            await Validation.validate_provider_async(errors, provider)
            if provider == "google":
                await Validation.validate_required_text_async(errors, "token", token)
                if errors:
                    return (
                        jsonify(
                            {
                                "errors": errors,
                                "message": "validations error",
                            }
                        ),
                        400,
                    )
                url = f"https://www.googleapis.com/oauth2/v3/userinfo?access_token={token}"
                response = requests.get(url)
                resp = response.json()
                try:
                    username = resp["name"]
                    email = resp["email"]
                    avatar = resp["picture"]
                except KeyError:
                    return (
                        jsonify(
                            {
                                "message": "validations error",
                            }
                        ),
                        400,
                    )
                if user_data := await UserDatabase.get("by_email", email=email):
                    return (
                        jsonify(
                            {
                                "message": "the user already exists",
                            }
                        ),
                        409,
                    )
                user_data = await UserDatabase.insert(
                    provider, avatar, username, email, None
                )
                user_me = self.user_seliazer.serialize(user_data)
                access_token = await AuthJwt.generate_jwt_async(
                    f"{user_data.id}", timestamp
                )
                access_token_model = AccessTokenSchema(
                    access_token=access_token, created_at=timestamp
                )
                token_data = self.token_serializer.serialize(access_token_model)
            else:
                await Validation.validate_username_async(errors, username)
                await Validation.validate_email_async(errors, email)
                await Validation.validate_password_async(
                    errors, password, confirm_password
                )
                if errors:
                    return (
                        jsonify(
                            {
                                "errors": errors,
                                "message": "validations error",
                            }
                        ),
                        400,
                    )
                result_password = bcrypt.generate_password_hash(password).decode(
                    "utf-8"
                )
                avatar = url_for(
                    "static", filename="images/default-avatar.webp", _external=True
                )
                if user_data := await UserDatabase.get("by_email", email=email):
                    return (
                        jsonify(
                            {
                                "message": "the user already exists",
                            }
                        ),
                        409,
                    )
            if provider != "google":
                user_data = await UserDatabase.insert(
                    provider,
                    f"{avatar}",
                    username,
                    email,
                    result_password,
                )
                user_me = self.user_seliazer.serialize(user_data)
            return (
                jsonify(
                    {
                        "message": "user registered successfully",
                        "data": user_me,
                    }
                ),
                201,
            )
        except Exception as e:
            return jsonify({"message": f"{e}"}), 400
