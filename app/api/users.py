import secrets

from flask import jsonify
from flask_login import current_user

from app.api import api_bp
from app.api.helpers import json_body, paginated_response
from app.extensions import db
from app.models.user import ROLES, User
from app.security.audit import record as audit_record
from app.security.rbac import ApiError, role_required


@api_bp.route("/users", methods=["GET"])
@role_required("ADMIN")
def list_users():
    return paginated_response(User.query.order_by(User.username), lambda u: u.to_dict())


@api_bp.route("/users", methods=["POST"])
@role_required("ADMIN")
def create_user():
    body = json_body()
    for field in ("username", "email", "full_name", "role"):
        if field not in body:
            raise ApiError("VALIDATION_ERROR", f"'{field}' is required", 422)
    if body["role"] not in ROLES:
        raise ApiError("VALIDATION_ERROR", f"role must be one of {ROLES}", 422)
    if User.query.filter_by(username=body["username"]).first():
        raise ApiError("VALIDATION_ERROR", "username already exists", 422)

    temp_password = body.get("password") or secrets.token_urlsafe(12)
    user = User(
        username=body["username"],
        email=body["email"],
        full_name=body["full_name"],
        role=body["role"],
        is_active_flag=body.get("is_active", True),
        must_change_password=True,
    )
    user.set_password(temp_password)
    db.session.add(user)
    db.session.commit()
    audit_record("USER_CREATED", user_id=current_user.user_id, detail=f"created={user.username}")

    response = user.to_dict()
    if not body.get("password"):
        response["temporary_password"] = temp_password  # shown once, admin must relay to the new user
    return jsonify(response), 201


@api_bp.route("/users/<int:user_id>", methods=["GET"])
@role_required("ADMIN")
def get_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        raise ApiError("NOT_FOUND", "User not found", 404)
    return jsonify(user.to_dict())


@api_bp.route("/users/<int:user_id>", methods=["PATCH"])
@role_required("ADMIN")
def update_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        raise ApiError("NOT_FOUND", "User not found", 404)
    body = json_body()

    if "role" in body:
        if body["role"] not in ROLES:
            raise ApiError("VALIDATION_ERROR", f"role must be one of {ROLES}", 422)
        user.role = body["role"]
    for field in ("email", "full_name"):
        if field in body:
            setattr(user, field, body[field])
    if "is_active" in body:
        user.is_active_flag = body["is_active"]
    if "password" in body and body["password"]:
        user.set_password(body["password"])
        user.must_change_password = True

    db.session.commit()
    audit_record("USER_UPDATED", user_id=current_user.user_id, detail=f"target={user.username}")
    return jsonify(user.to_dict())


@api_bp.route("/users/<int:user_id>", methods=["DELETE"])
@role_required("ADMIN")
def delete_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        raise ApiError("NOT_FOUND", "User not found", 404)
    user.is_active_flag = False
    db.session.commit()
    audit_record("USER_DEACTIVATED", user_id=current_user.user_id, detail=f"target={user.username}")
    return "", 204
