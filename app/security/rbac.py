"""Server-side role-based access control. UI hiding is cosmetic only — this is the control (NFR5.4)."""
from functools import wraps

from flask import jsonify, request
from flask_login import current_user


class ApiError(Exception):
    def __init__(self, code, message, status=400, details=None):
        self.code = code
        self.message = message
        self.status = status
        self.details = details or {}

    def to_response(self):
        return jsonify({"error": {"code": self.code, "message": self.message, "details": self.details}}), self.status


def role_required(*roles):
    """Restrict a view to the given roles. Returns 401 if unauthenticated, 403 if wrong role."""

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                if request.blueprint == "api" or request.path.startswith("/api/"):
                    raise ApiError("UNAUTHENTICATED", "Login required", 401)
                from flask import redirect, url_for

                return redirect(url_for("auth.login", next=request.path))
            if roles and current_user.role not in roles:
                raise ApiError("FORBIDDEN", "Insufficient role for this action", 403)
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def login_required_any(fn):
    return role_required(*[])(fn)
