import os
import base64
import hashlib
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash
from pymisp import PyMISP, MISPEvent, MISPAttribute
from werkzeug.utils import secure_filename
from misp_connect import get_api_key_for_org, get_available_organisations  # Import from misp_connect

ransomware_bp = Blueprint('ransomware', __name__, template_folder='../templates')

@ransomware_bp.route('/ransomware', methods=['GET', 'POST'])
def ransomware():
    available_organisations = get_available_organisations()

    if request.method == 'POST':
        try:
            selected_org = request.form.get('organisation')
            MISP_API_KEY = get_api_key_for_org(selected_org)

            if not MISP_API_KEY:
                flash("Invalid organisation selected. Please try again.", "danger")
                return redirect(url_for('ransomware.ransomware'))

            MISP_URL = os.getenv('MISP_URL')
            MISP_VERIFY_SSL = os.getenv('MISP_VERIFY_SSL', 'False').lower() == 'true'
            misp = PyMISP(MISP_URL, MISP_API_KEY, MISP_VERIFY_SSL)

            # Collect form data
            ransomware_name = request.form.get('ransomware_name')
            ransom_amount = request.form.get('ransom_amount')
            ransom_currency = request.form.get('ransom_amount_currency', 'USD')
            btc_address = request.form.get('btc_address')
            description = request.form.get('description')
            date = request.form.get('date', datetime.today().strftime('%Y-%m-%d'))
            time = request.form.get('time')
            full_name = request.form.get('person_name')
            email = request.form.get('person_email')
            phone_number = request.form.get('person_phone')
            ransomware_file = request.files.get('ransomware_file')  # Malware sample
            ransomware_screenshot = request.files.get('ransomware_screenshot')  # Screenshot of ransom note

            distribution = int(request.form.get('distribution', 0))
            threat_level_id = int(request.form.get('threat_level_id', 4))
            analysis = int(request.form.get('analysis', 2))
            tlp = request.form.get('tlp')

            # Create MISP event
            misp_event = MISPEvent()
            misp_event.info = f"Ransomware Attack Report - ({ransomware_name})"
            misp_event.date = date
            misp_event.distribution = distribution
            misp_event.threat_level_id = threat_level_id
            misp_event.analysis = analysis
            misp_event.add_tag('circl:incident-classification="ransomware"')
            misp_event.add_tag('circl:incident-classification="malware"')
            misp_event.add_tag('circl:incident-classification="system-compromise"')
            misp_event.add_tag('source:UnderServed')
            misp_event.add_tag('source:MISP-Forms')
            misp_event.add_tag('misp-galaxy:mitre-attack-pattern="Data Encrypted for Impact - T1486"')  # ransom


            if tlp:
                misp_event.add_tag(tlp)

            event = misp.add_event(misp_event)
            event_id = event['Event']['id']

            # Add attributes
            add_attribute(misp, event_id, category="Financial fraud",  type="text", value=f"{ransom_amount} {ransom_currency}", comment="Ransom Amount")
            if btc_address:
                add_attribute(misp, event_id, category="Financial fraud",  type="btc", value=btc_address, comment="Bitcoin Address")
            if description:
                add_attribute(misp, event_id, category="Other",  type="text", value=description, comment="Ransomware Description")
            if time:
                add_attribute(misp, event_id, category="Other",  type="datetime", value=f"{date} {time}", comment="Date and Time of Attack")

            if full_name:
                add_attribute(misp, event_id, category="Person",  type="full-name", value=full_name, comment="Victim Full Name")
            if email:
                add_attribute(misp, event_id, category="Person",  type="email", value=email, comment="Victim Email")
            if phone_number:
                add_attribute(misp, event_id, category="Person",  type="phone-number", value=phone_number, comment="Victim Phone Number")

            # ransomware sample (malware file) upload
            if ransomware_file and allowed_ransomware_file(ransomware_file.filename):
                process_uploaded_file(misp, event_id, ransomware_file, category="Payload delivery",  type="malware-sample", comment="Ransomware Sample")

            # ransomware screenshot (ransom note) upload
            if ransomware_screenshot and allowed_screenshot_file(ransomware_screenshot.filename):
                process_uploaded_file(misp, event_id, ransomware_screenshot, category="External analysis",  type="attachment", comment="Ransomware Pop-Up Screenshot")

            flash(
                '✅ Report submitted successfully - Thank you! <br><br> Need advice on <strong>Recovery</strong> or <strong>Mitigation?</strong> <a href="https://mkdocs.underserved.org/ransomware/" target="_blank">[Click Here]</a>',
                'light')
            return redirect(url_for('ransomware.ransomware'))

        except Exception as e:
            flash(f"An error occurred: {e}", "danger")
            return redirect(url_for('ransomware.ransomware'))

    return render_template('ransomware.html', available_organisations=available_organisations, today_date=datetime.today().strftime('%Y-%m-%d'))


def add_attribute(misp, event_id, category,  type, value, data=None, comment=None):
    attribute = MISPAttribute()
    attribute.category = category
    attribute.type =  type
    attribute.value = value
    if data:
        attribute.data = data  # Attach file data (for malware samples/screenshots)
    if comment:
        attribute.comment = comment
    response = misp.add_attribute(event_id, attribute)
    return response


def process_uploaded_file(misp, event_id, file, category,  type, comment):
    filename = secure_filename(file.filename)
    file_content = file.read()

    md5_hash = hashlib.md5(file_content).hexdigest()
    sha256_hash = hashlib.sha256(file_content).hexdigest()
    sha512_hash = hashlib.sha512(file_content).hexdigest()
    encoded_data = base64.b64encode(file_content).decode('utf-8')

    add_attribute(misp, event_id, category,  type="filename", value=filename, comment=f"{comment} Filename")
    add_attribute(misp, event_id, category,  type="md5", value=md5_hash, comment=f"{comment} MD5 Hash")
    add_attribute(misp, event_id, category,  type="sha256", value=sha256_hash, comment=f"{comment} SHA256 Hash")
    add_attribute(misp, event_id, category,  type="sha512", value=sha512_hash, comment=f"{comment} SHA512 Hash")

    if  type == "malware-sample":
        add_attribute(misp, event_id, category,  type="malware-sample", value=filename, data=encoded_data, comment=f"{comment} File Uploaded")

    if  type == "attachment":
        add_attribute(misp, event_id, category,  type="attachment", value=filename, data=encoded_data, comment=f"{comment} Screenshot Uploaded")


def allowed_ransomware_file(filename):
    allowed_extensions = {'exe', 'dll', 'bin', 'jar', 'ps1', 'vbs', 'js'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions


def allowed_screenshot_file(filename):
    allowed_extensions = {'png', 'jpg', 'jpeg', 'pdf'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions
