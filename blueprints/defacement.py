import base64
import json
import os
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash
from pymisp import PyMISP, MISPEvent, MISPAttribute, MISPObject
from werkzeug.utils import secure_filename
from misp_connect import get_api_key_for_org, get_available_organisations

defacement_bp = Blueprint('defacement', __name__, template_folder='templates')


@defacement_bp.route('/web_defacement', methods=['GET', 'POST'])
def web_defacement():
    MISP_URL = os.getenv('MISP_URL')
    MISP_VERIFY_SSL = os.getenv('MISP_VERIFY_SSL', 'False').lower() == 'true'
    available_organisations = get_available_organisations()  # Get list dynamically

    if request.method == 'POST':
        selected_org = request.form.get('organisation')
        MISP_API_KEY = get_api_key_for_org(selected_org)

        if not MISP_API_KEY:
            flash("Invalid organisation selected. Please try again.", "danger")
            return redirect(url_for('defacement.web_defacement'))

        misp = PyMISP(MISP_URL, MISP_API_KEY, MISP_VERIFY_SSL)

        try:
            # Collect form data
            url = request.form.get('url')
            attacker_ip = request.form.get('attacker_ip')
            defacement_message = request.form.get('defacement_message')
            vulnerability = request.form.get('vulnerability')
            screenshot = request.files.get('screenshot')
            description = request.form.get('description')
            threat_actor = request.form.get('threat_actor')
            date = request.form.get('date', datetime.today().strftime('%Y-%m-%d'))
            time = request.form.get('time')

            distribution = int(request.form.get('distribution', 0))
            threat_level_id = int(request.form.get('threat_level_id', 4))
            analysis = int(request.form.get('analysis', 0))
            tlp = request.form.get('tlp')

            if not url:
                flash("Website URL is a required field.", "danger")
                return redirect(url_for('defacement.web_defacement'))

            # Create MISP event
            misp_event = MISPEvent()
            misp_event.info = f"Website Defacement Report - {url}"
            misp_event.distribution = distribution
            misp_event.threat_level_id = threat_level_id
            misp_event.analysis = analysis
            date = request.form.get('date', datetime.today().strftime('%Y-%m-%d'))
            time = request.form.get('time')
            if tlp:
                misp_event.add_tag(tlp)
            misp_event.add_tag('rsit:intrusions="system-compromise"')
            misp_event.add_tag('rsit:intrusions="application-compromise"')
            misp_event.add_tag('misp-galaxy:mitre-attack-pattern="Defacement - T1491"')  # website defacement
            misp_event.add_tag('misp-galaxy:mitre-attack-pattern="External Defacement - T1491.002"')  # website defacemen
            misp_event.add_tag('source:UnderServed')
            misp_event.add_tag('source:MISP-Forms')


            event = misp.add_event(misp_event)
            event_id = event['Event']['id']

            # mao form data to misp attributes,  comments also included
            add_attribute(misp, event_id, category="Network activity", type="url", value=url)
            if attacker_ip:
                add_attribute(misp, event_id, category="Network activity", type="ip-src", value=attacker_ip)
            if defacement_message:
                add_attribute(misp, event_id, category="Other", type="text", value=defacement_message, comment="Defacement message")
            if vulnerability:
                add_attribute(misp, event_id, category="External analysis", type="vulnerability", value=vulnerability)
            if description:
                add_attribute(misp, event_id, category="Other", type="text", value=description, comment="Overview of incident")
            if threat_actor:
                add_attribute(misp, event_id, category="Attribution", type="threat-actor", value=threat_actor)
            if time:
                add_attribute(misp, event_id, category="Other", type="datetime", value=f"{date} {time}",
                              comment="Date and Time of Attack")

            # get screenshot using base64-encoding
            if screenshot and allowed_file(screenshot.filename):
                filename = secure_filename(screenshot.filename)
                file_content = screenshot.read()
                encoded_data = base64.b64encode(file_content).decode('utf-8')

                file_object = MISPObject('file')
                file_object.add_attribute('filename', value=filename)
                file_object.add_attribute('attachment', data=encoded_data, value=filename)
                misp.add_object(event_id, file_object)

            flash('✅ Report submitted successfully - Thank you!', 'light')

            return redirect(url_for('defacement.web_defacement'))
        except Exception as e:
            flash(f"An error occurred: {e}", "danger")

        return redirect(url_for('defacement.web_defacement'))

    return render_template('defacement.html', available_organisations=available_organisations,today_date=datetime.today().strftime('%Y-%m-%d'))


def add_attribute(misp, event_id, category, type, value, comment=None):
    attribute = MISPAttribute()
    attribute.category = category
    attribute.type = type
    attribute.value = value
    if comment:
        attribute.comment = comment
    misp.add_attribute(event_id, attribute)


# limit extension type. More needed?  Add new ext to list to allow upload.
def allowed_file(filename):
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions
