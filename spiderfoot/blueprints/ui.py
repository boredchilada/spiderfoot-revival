from flask import Blueprint, render_template

from spiderfoot.__version__ import __version__

ui_bp = Blueprint('ui', __name__)


@ui_bp.route('/')
def dashboard():
    return render_template(
        'pages/dashboard.html',
        page_id='DASHBOARD',
        version=__version__,
    )


@ui_bp.route('/newscan')
def newscan():
    return render_template(
        'pages/scan_new.html',
        page_id='NEWSCAN',
        version=__version__,
    )


@ui_bp.route('/scaninfo')
def scaninfo():
    return render_template(
        'pages/scan_results.html',
        page_id='SCANINFO',
        version=__version__,
    )


@ui_bp.route('/opts')
def settings():
    return render_template(
        'pages/settings.html',
        page_id='SETTINGS',
        version=__version__,
    )
