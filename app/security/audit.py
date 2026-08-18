from flask import request

from app.extensions import db
from app.models.audit_log import AuditLog


def record(event, user_id=None, detail=None):
    entry = AuditLog(
        user_id=user_id,
        event=event,
        detail=detail,
        ip_address=request.remote_addr if request else None,
    )
    db.session.add(entry)
    db.session.commit()
    return entry
