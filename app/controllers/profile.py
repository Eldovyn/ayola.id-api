from ..databases import UserDatabase
from flask import jsonify, send_from_directory, request, make_response
from ..utils import SendEmail
from email_validator import validate_email
from ..serializers import UserSerializer
from werkzeug.utils import secure_filename
import os
import cloudinary.uploader
from ..utils import generate_etag


class ProfileController:
    def __init__(self):
        self.user_seliazer = UserSerializer()

    async def default_avatar(self):
        return send_from_directory(
            "static/images", "default-avatar.webp", mimetype="image/png"
        )

    async def current_user(self, user):
        current_user = self.user_seliazer.serialize(user)

        etag = generate_etag(current_user)

        client_etag = request.headers.get("If-None-Match")
        if client_etag == etag:
            return make_response("", 304)

        response_data = {
            "data": current_user,
            "message": "successfully get user",
        }

        response = make_response(jsonify(response_data), 200)
        response.headers["Content-Type"] = "application/json"
        response.headers["ETag"] = etag
        return response
