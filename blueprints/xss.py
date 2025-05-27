import base64
from datetime import datetime
import os
from flask import Blueprint, render_template, request, redirect, url_for, flash
from pymisp import PyMISP, MISPEvent, MISPObject, MISPAttribute
from werkzeug.utils import secure_filename
from misp_connect import get_api_key_for_org, get_available_organisations  # Import from misp_connect

xss_bp = Blueprint('xss', __name__, template_folder='../templates')

@xss_bp.route('/xss', methods=['GET', 'POST'])
def xss():
    available_organisations = get_available_organisations()

    if request.method == 'POST':
        try:
            selected_org = request.form.get('organisation')
            MISP_API_KEY = get_api_key_for_org(selected_org)

            if not MISP_API_KEY:
                flash("Invalid organisation selected. Please try again.", "danger")
                return redirect(url_for('xss.xss'))

            MISP_URL = os.getenv('MISP_URL')
            MISP_VERIFY_SSL = os.getenv('MISP_VERIFY_SSL', 'False').lower() == 'true'
            misp = PyMISP(MISP_URL, MISP_API_KEY, MISP_VERIFY_SSL)

            # Collect form data
            url = request.form.get('url')
            attacker_ip = request.form.get('attacker_ip')
            victim_ip = request.form.get('victim_ip')
            vulnerability = request.form.get('vulnerability')
            xss_payload = request.form.get('xss_payload')
            description = request.form.get('description')
            threat_actor = request.form.get('threat_actor')
            date = request.form.get('date', datetime.now().strftime('%Y-%m-%d'))
            time = request.form.get('time')
            screenshot = request.files.get('screenshot')

            distribution = int(request.form.get('distribution', 0))
            threat_level_id = int(request.form.get('threat_level_id', 4))
            analysis = int(request.form.get('analysis', 0))
            tlp = request.form.get('tlp')

            if not url:
                flash("Website URL is a required field.", "danger")
                return redirect(url_for('xss.xss'))

            # Create MISP event
            misp_event = MISPEvent()
            misp_event.info = f"XSS Report - {url}"
            misp_event.date = date
            misp_event.distribution = distribution
            misp_event.threat_level_id = threat_level_id
            misp_event.analysis = analysis
            misp_event.add_tag('circl:incident-classification="XSS"')
            misp_event.add_tag('rsit:intrusions="application-compromise"')
            misp_event.add_tag('source:UnderServed')
            misp_event.add_tag('source:MISP-Forms')
            misp_event.add_tag('misp-galaxy:mitre-attack-pattern="Compromise of externally facing system - T1388"')


            if tlp:
                misp_event.add_tag(tlp)

            event = misp.add_event(misp_event)
            event_id = event['Event']['id']

            # Add attributes
            add_attribute(misp, event_id, category="Network activity", attr_type="url", value=url, comment="Target URL")
            if attacker_ip:
                add_attribute(misp, event_id, category="Network activity", attr_type="ip-src", value=attacker_ip, comment="Attacker IP")
            if victim_ip:
                add_attribute(misp, event_id, category="Network activity", attr_type="ip-dst", value=victim_ip, comment="Victim IP")
            if vulnerability:
                add_attribute(misp, event_id, category="External analysis", attr_type="vulnerability", value=vulnerability, comment="Known Exploited Vulnerability")
            if xss_payload:
                add_attribute(misp, event_id, category="Payload delivery", attr_type="text", value=xss_payload, comment="XSS Payload Used")
            if description:
                add_attribute(misp, event_id, category="Other", attr_type="text", value=description, comment="Incident Overview")
            if threat_actor:
                add_attribute(misp, event_id, category="Attribution", attr_type="threat-actor", value=threat_actor, comment="Suspected Threat Actor")
            if time:
                add_attribute(misp, event_id, category="Other", attr_type="datetime", value=f"{date} {time}", comment="Date and Time of Attack")

            # Screenshot upload
            if screenshot and allowed_screenshot_file(screenshot.filename):
                process_uploaded_file(misp, event_id, screenshot, category="External analysis", attr_type="attachment", comment="Screenshot of XSS Attack")

            flash(
                '✅ Report submitted successfully - Thank you!',
                'light')

            return redirect(url_for('xss.xss'))

        except Exception as e:
            flash(f"An error occurred: {e}", "danger")
            return redirect(url_for('xss.xss'))

    return render_template('xss.html', available_organisations=available_organisations, today_date=datetime.today().strftime('%Y-%m-%d'))


def add_attribute(misp, event_id, category, attr_type, value, data=None, comment=None):
    attribute = MISPAttribute()
    attribute.category = category
    attribute.type = attr_type
    attribute.value = value
    if data:
        attribute.data = data
    if comment:
        attribute.comment = comment
    response = misp.add_attribute(event_id, attribute)
    return response


def process_uploaded_file(misp, event_id, file, category, attr_type, comment):
    filename = secure_filename(file.filename)
    file_content = file.read()

    encoded_data = base64.b64encode(file_content).decode('utf-8')

    file_object = MISPObject('file')
    file_object.add_attribute('filename', value=filename)
    file_object.add_attribute('attachment', data=encoded_data, value=filename, comment=comment)
    misp.add_object(event_id, file_object)


def allowed_screenshot_file(filename):
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions
