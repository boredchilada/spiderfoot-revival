from flask import Blueprint

ui_bp = Blueprint('ui', __name__)


@ui_bp.route('/')
def index():
    return '<h1>SpiderFoot</h1><p>UI coming soon</p>'
