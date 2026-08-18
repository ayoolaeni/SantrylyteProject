from datetime import datetime, timezone

from flask import jsonify, request

from app.security.rbac import ApiError

DEFAULT_PER_PAGE = 50
MAX_PER_PAGE = 200


def list_param(name):
    raw = request.args.get(name)
    if not raw:
        return None
    return [v.strip() for v in raw.split(",") if v.strip()]


def parse_iso(value):
    if not value:
        return None
    try:
        ts = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts
    except ValueError:
        raise ApiError("INVALID_PARAM", f"Invalid ISO timestamp: {value}", 400)


def paginated_response(query, serializer):
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        raise ApiError("INVALID_PARAM", "page must be an integer", 400)
    try:
        per_page = min(MAX_PER_PAGE, max(1, int(request.args.get("per_page", DEFAULT_PER_PAGE))))
    except ValueError:
        raise ApiError("INVALID_PARAM", "per_page must be an integer", 400)

    total = query.count()
    items = query.offset((page - 1) * per_page).limit(per_page).all()
    return jsonify(
        {
            "data": [serializer(item) for item in items],
            "page": page,
            "per_page": per_page,
            "total": total,
        }
    )


def json_body():
    body = request.get_json(silent=True)
    if body is None:
        raise ApiError("INVALID_BODY", "Expected a JSON request body", 400)
    return body
