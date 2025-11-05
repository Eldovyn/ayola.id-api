from .reset_password_changed import *
from .validate_register import *
from .validate_login import *


def register_socket_io(socket_io):
    register_reset_password_changed_socketio_events(socket_io)
    register_validate_register_socketio_events(socket_io)
    register_validate_login_socketio_events(socket_io)
