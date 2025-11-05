from ..databases import (
    UserDatabase,
)
from flask import jsonify
import requests
from ..utils import (
    AuthJwt,
    Validation,
)
from ..serializers import UserSerializer, TokenSerializer
from ..dataclasses import AccessTokenSchema
import traceback


class LoginController:
    def __init__(self):
        self.user_seliazer = UserSerializer()
        self.token_serializer = TokenSerializer()

    async def user_login(self, provider, token, email, password, timestamp):
        from ..extensions import bcrypt

        access_token = None

        try:
            errors = {}
            await Validation.validate_provider_async(errors, provider)

            if provider == "google":
                await Validation.validate_required_text_async(errors, "token", token)
                if errors:
                    return (
                        jsonify({"errors": errors, "message": "validations error"}),
                        400,
                    )
                url = f"https://www.googleapis.com/oauth2/v3/userinfo?access_token={token}"
                response = requests.get(url)
                resp = response.json()
                try:
                    email = resp["email"]
                except KeyError:
                    return (
                        jsonify(
                            {
                                "errors": {"token": ["IS_INVALID"]},
                                "message": "validations error",
                            }
                        ),
                        400,
                    )
                if not (user_data := await UserDatabase.get("by_email", email=email)):
                    return (
                        jsonify(
                            {
                                "message": "you are not registered",
                            }
                        ),
                        401,
                    )
                if not user_data.is_active:
                    return (
                        jsonify(
                            {
                                "message": "user is not active",
                            }
                        ),
                        403,
                    )
                if not user_data.provider == "google":
                    return (
                        jsonify(
                            {
                                "message": "you are not registered",
                            }
                        ),
                        401,
                    )
                access_token = await AuthJwt.generate_jwt_async(
                    f"{user_data.id}", timestamp
                )
                user_me = self.user_seliazer.serialize(user_data)
            else:
                await Validation.validate_required_text_async(errors, "email", email)
                await Validation.validate_required_text_async(
                    errors, "password", password
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
                if not (user_data := await UserDatabase.get("by_email", email=email)):
                    return (
                        jsonify(
                            {
                                "message": "invalid email or password",
                            }
                        ),
                        401,
                    )
                if not bcrypt.check_password_hash(user_data.password, password):
                    return (
                        jsonify(
                            {
                                "message": "invalid email or password",
                            }
                        ),
                        401,
                    )
                access_token = await AuthJwt.generate_jwt_async(
                    f"{user_data.id}", timestamp
                )
                user_me = self.user_seliazer.serialize(user_data)
            token_model = AccessTokenSchema(access_token, timestamp)
            token_data = self.token_serializer.serialize(token_model)
            return (
                jsonify(
                    {
                        "message": "user login successfully",
                        "data": user_me,
                        "token": token_data,
                    }
                ),
                201,
            )
        except Exception:
            traceback.print_exc()
            return jsonify({"message": "invalid request"}), 400
