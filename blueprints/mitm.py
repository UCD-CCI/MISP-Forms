import os
import base64
import hashlib
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash
from pymisp import PyMISP, MISPEvent, MISPAttribute
from werkzeug.utils import secure_filename
from misp_connect import get_api_key_for_org, get_available_organisations  # Import from misp_connect

mitm_bp = Blueprint('mitm', __name__, template_folder='../templates')

@mitm_bp.route('/mitm', methods=['GET', 'POST'])
def mitm():
    available_organisations = get_available_organisations()

    if request.method == 'POST':
        try:
            selected_org = request.form.get('organisation')
            MISP_API_KEY = get_api_key_for_org(selected_org)

            if not MISP_API_KEY:
                flash("Invalid organisation selected. Please try again.", "danger")
                return redirect(url_for('mitm.mitm'))

            MISP_URL = os.getenv('MISP_URL')
            MISP_VERIFY_SSL = os.getenv('MISP_VERIFY_SSL', 'False').lower() == 'true'
            misp = PyMISP(MISP_URL, MISP_API_KEY, MISP_VERIFY_SSL)

            # Collect form data
            attacker_ip = request.form.get('attacker_ip')
            victim_ip = request.form.get('victim_ip')
            affected_service = request.form.get('affected_service')
            protocol_used = request.form.get('protocol_used')
            captured_data = request.form.get('captured_data')
            date = request.form.get('date', datetime.today().strftime('%Y-%m-%d'))
            time = request.form.get('time')
            screenshot_file = request.files.get('screenshot_file')
            tlp = request.form.get('tlp')

            # Create MISP event
            misp_event = MISPEvent()
            misp_event.info = f"Man-in-the-Middle Attack - {affected_service}"
            misp_event.distribution = int(request.form.get('distribution', 0))
            misp_event.threat_level_id = int(request.form.get('threat_level_id', 4))
            misp_event.analysis = int(request.form.get('analysis', 2))
            misp_event.add_tag("type:mitm")
            misp_event.add_tag('misp-galaxy:financial-fraud="MITM - Man-in-the-Middle Attack"')  # MITM
            misp_event.add_tag('misp-galaxy:mitre-attack-pattern="Adversary-in-the-Middle - T1557"')  # MITM
            misp_event.add_tag('source:UnderServed')
            misp_event.add_tag('source:MISP-Forms')
            misp_event.add_tag(f"protocol:{protocol_used}")
            threat_actor = request.form.get('threat_actor')
            vulnerability = request.form.get('vulnerability')
            tlp = request.form.get('tlp')

            if tlp:
                misp_event.add_tag(tlp)

            event = misp.add_event(misp_event)
            event_id = event['Event']['id']


            # Add attributes
            add_attribute(misp, event_id, category="Network activity",  type="ip-src", value=attacker_ip, comment="Attacker IP Address")
            add_attribute(misp, event_id, category="Network activity",  type="ip-dst", value=victim_ip, comment="Victim IP Address")
            add_attribute(misp, event_id, category="Network activity",  type="service", value=affected_service, comment="Affected Service")

            if protocol_used:
                add_attribute(misp, event_id, category="Network activity",  type="protocol", value=protocol_used, comment="Protocol Used")
            if captured_data:
                add_attribute(misp, event_id, category="Payload delivery",  type="text", value=captured_data, comment="Captured MITM Data")
            if time:
                add_attribute(misp, event_id, category="Other",  type="datetime", value=f"{date} {time}", comment="Date and Time of Attack")
            if vulnerability:
                add_attribute(misp, event_id, category="External analysis", type="vulnerability", value=vulnerability)
            if threat_actor:
                add_attribute(misp, event_id, category="Attribution", type="threat-actor", value=threat_actor)

            # screenshot upload
            if screenshot_file and allowed_screenshot_file(screenshot_file.filename):
                process_uploaded_file(misp, event_id, screenshot_file, category="External analysis",  type="attachment", comment="Screenshot of MITM Attack")

            flash(
                '✅ Report submitted successfully - Thank you!',
                'light')
            return redirect(url_for('mitm.mitm'))

        except Exception as e:
            flash(f"An error occurred: {e}", "danger")
            return redirect(url_for('mitm.mitm'))

    return render_template('mitm.html', available_organisations=available_organisations, today_date=datetime.today().strftime('%Y-%m-%d'))


def add_attribute(misp, event_id, category,  type, value, data=None, comment=None):
    attribute = MISPAttribute()
    attribute.category = category
    attribute.type =  type
    attribute.value = value
    if data:
        attribute.data = data  # Attach screenshot file
    if comment:
        attribute.comment = comment
    response = misp.add_attribute(event_id, attribute)
    return response


def process_uploaded_file(misp, event_id, file, category,  type, comment):
    filename = secure_filename(file.filename)
    file_content = file.read()

    # Calculate hashes
    md5_hash = hashlib.md5(file_content).hexdigest()
    sha256_hash = hashlib.sha256(file_content).hexdigest()
    sha512_hash = hashlib.sha512(file_content).hexdigest()
    encoded_data = base64.b64encode(file_content).decode('utf-8')

    # Add file attributes
    add_attribute(misp, event_id, category,  type="filename", value=filename, comment=f"{comment} Filename")
    add_attribute(misp, event_id, category,  type="md5", value=md5_hash, comment=f"{comment} MD5 Hash")
    add_attribute(misp, event_id, category,  type="sha256", value=sha256_hash, comment=f"{comment} SHA256 Hash")
    add_attribute(misp, event_id, category,  type="sha512", value=sha512_hash, comment=f"{comment} SHA512 Hash")

    # Attach screenshot as an attribute
    add_attribute(misp, event_id, category,  type="attachment", value=filename, data=encoded_data, comment=f"{comment} Screenshot Uploaded")


def allowed_screenshot_file(filename):
    allowed_extensions = {'png', 'jpg', 'jpeg', 'pdf'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions
