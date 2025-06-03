import os
import base64
import hashlib
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash
from pymisp import PyMISP, MISPEvent, MISPAttribute
from werkzeug.utils import secure_filename
from misp_connect import get_api_key_for_org, get_available_organisations  # Import from misp_connect

phishing_bp = Blueprint('phishing', __name__, template_folder='../templates')

@phishing_bp.route('/phishing_choice')
def phishing_choice():
    return render_template('phishing_choice.html')


@phishing_bp.route('/phishing', methods=['GET', 'POST'])
def phishing():
    available_organisations = get_available_organisations()

    if request.method == 'POST':
        try:
            selected_org = request.form.get('organisation')
            MISP_API_KEY = get_api_key_for_org(selected_org)

            if not MISP_API_KEY:
                flash("Invalid organisation selected. Please try again.", "danger")
                return redirect(url_for('phishing.phishing'))

            MISP_URL = os.getenv('MISP_URL')
            MISP_VERIFY_SSL = os.getenv('MISP_VERIFY_SSL', 'False').lower() == 'true'
            misp = PyMISP(MISP_URL, MISP_API_KEY, MISP_VERIFY_SSL)

            email_sender = request.form.get('email_sender')
            subject = request.form.get('subject')
            body = request.form.get('body')
            urls = request.form.get('urls', '').splitlines()
            attachment = request.files.get('attachment')
            date = request.form.get('date', datetime.today().strftime('%Y-%m-%d'))

            if not email_sender or not subject:
                flash("Email sender and subject are required fields.", "danger")
                return redirect(url_for('phishing.phishing'))

            # Create MISP event
            misp_event = MISPEvent()
            misp_event.info = f"Phishing Email Report - {subject}"
            misp_event.date = date
            misp_event.distribution = int(request.form.get('distribution', 0))
            misp_event.threat_level_id = int(request.form.get('threat_level_id', 4))
            misp_event.analysis = int(request.form.get('analysis', 2))
            misp_event.add_tag('rsit:fraud="phishing"')
            misp_event.add_tag('circl: incident - classification = "phishing"')
            misp_event.add_tag('tlp:red')  # currently fixed, not changed by sharing option on form
            misp_event.add_tag('source:UnderServed')
            misp_event.add_tag('source:MISP-Forms')
            misp_event.add_tag('misp-galaxy:mitre-attack-pattern="Phishing - T1660"')  # phishing
            misp_event.add_tag('misp-galaxy:mitre-attack-pattern="Phishing for Information - T1598"')  # phishing

            event = misp.add_event(misp_event)
            event_id = event['Event']['id']

            # map arributes from form inputs
            add_attribute(misp, event_id, category="Payload delivery", attr_type="email-src", value=email_sender, comment="Phishing Email Sender")
            add_attribute(misp, event_id, category="Payload delivery", attr_type="email-subject", value=subject, comment="Email Subject")
            add_attribute(misp, event_id, category="Payload delivery", attr_type="text", value=body, comment="Email Body Content")

            # Add URLs if found
            for url in urls:
                if url.strip():
                    add_attribute(misp, event_id, category="Network activity", attr_type="url", value=url.strip(), comment="Extracted URL from Email")

            # get attacments
            if attachment and attachment.filename != '':
                process_uploaded_file(misp, event_id, attachment, category="Payload delivery", attr_type="attachment", comment="Phishing Email Attachment")
                # get SHA256
                file_path = f"/tmp/{attachment.filename}"
                attachment.save(file_path)
                sha256_hash = hashlib.sha256()
                with open(file_path, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        sha256_hash.update(chunk)
                attachment_sha256 = sha256_hash.hexdigest()
                add_attribute(misp, event_id, category="Payload delivery", attr_type="sha256", value=attachment_sha256, comment="SHA256 of Email Attachment")

            flash(
                '✅ Report submitted successfully - Thank you!',
                'light')
            return redirect(url_for('phishing.phishing'))

        except Exception as e:
            flash(f"An error occurred: {e}", "danger")
            return redirect(url_for('phishing.phishing'))

    return render_template('phishing.html', available_organisations=available_organisations, today_date=datetime.today().strftime('%Y-%m-%d'))


def add_attribute(misp, event_id, category, attr_type, value, data=None, comment=None):
    attribute = MISPAttribute()
    attribute.category = category
    attribute.type = attr_type
    attribute.value = value
    if data:
        attribute.data = data  # Attach file content if needed
    if comment:
        attribute.comment = comment
    response = misp.add_attribute(event_id, attribute)
    return response


def process_uploaded_file(misp, event_id, file, category, attr_type, comment):
    filename = secure_filename(file.filename)
    file_content = file.read()

    md5_hash = hashlib.md5(file_content).hexdigest()
    sha256_hash = hashlib.sha256(file_content).hexdigest()
    sha512_hash = hashlib.sha512(file_content).hexdigest()
    encoded_data = base64.b64encode(file_content).decode('utf-8')

    add_attribute(misp, event_id, category, attr_type="filename", value=filename, comment=f"{comment} Filename")
    add_attribute(misp, event_id, category, attr_type="md5", value=md5_hash, comment=f"{comment} MD5 Hash")
    add_attribute(misp, event_id, category, attr_type="sha256", value=sha256_hash, comment=f"{comment} SHA256 Hash")
    add_attribute(misp, event_id, category, attr_type="sha512", value=sha512_hash, comment=f"{comment} SHA512 Hash")


    add_attribute(misp, event_id, category, attr_type="attachment", value=filename, data=encoded_data, comment=f"{comment} Attachment Uploaded")


# limit file types,  add more to list if required,  avoid exes.  These should be handled with Pandora
def allowed_attachment_file(filename):
    allowed_extensions = {'eml', 'pdf', 'docx', 'xlsx', 'zip', 'rar'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions
