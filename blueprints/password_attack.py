import os
import base64
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash
from pymisp import PyMISP, MISPEvent
from werkzeug.utils import secure_filename
from misp_connect import get_api_key_for_org, get_available_organisations

password_attack_bp = Blueprint('password_attack', __name__, template_folder='../templates')

@password_attack_bp.route('/password_attack', methods=['GET', 'POST'])
def password_attack():
    available_organisations = get_available_organisations()

    if request.method == 'POST':
        try:
            organisation = request.form.get('organisation')
            if not organisation:
                flash("You must select an organisation.", "danger")
                return redirect(url_for('password_attack.password_attack'))

            misp_api_key = get_api_key_for_org(organisation)
            if not misp_api_key:
                flash("Invalid organisation selection.", "danger")
                return redirect(url_for('password_attack.password_attack'))

            # Initialize PyMISP correctly
            misp = PyMISP(os.getenv('MISP_URL'), misp_api_key, os.getenv('MISP_VERIFY_SSL', 'False').lower() == 'true')

            # Collect form data
            source_ip = request.form.get('source_ip')
            domain_name = request.form.get('domain_name')
            target_ip = request.form.get('target_ip')
            target_url = request.form.get('target_url')
            service = request.form.get('service')
            attack_type = request.form.get('attack_type')
            attack_datetime = request.form.get('attack_datetime')
            log_file = request.files.get('log_file')
            tlp = request.form.get('tlp')
            description = request.form.get('description')

            # Validate required fields
            # if not source_ip or not target_ip or not service:
            #     flash("Source IP, Target IP, and Service are required fields.", "danger")
            #     return redirect(url_for('password_attack.password_attack'))

            # Create a MISP Event
            misp_event = MISPEvent()
            misp_event.info = f"Password Attack Report - {service}"
            misp_event.date = datetime.today().strftime('%Y-%m-%d')
            misp_event.distribution = int(request.form.get('distribution', 0))
            misp_event.threat_level_id = int(request.form.get('threat_level_id', 4))
            misp_event.analysis = int(request.form.get('analysis', 0))
            misp_event.add_tag('rsit:intrusion-attempts="brute-force"')
            misp_event.add_tag('misp-galaxy:mitre-attack-pattern="Brute Force - T1110"')  # password
            misp_event.add_tag('source:UnderServed')
            misp_event.add_tag('source:MISP-Forms')
            misp_event.add_tag(f"service:{service.lower()}")
            tlp = request.form.get('tlp')

            if tlp:
                misp_event.add_tag(tlp)

            # Submit the event to MISP
            event = misp.add_event(misp_event)
            event_id = event['Event']['id']

            # Add attributes
            add_attribute(misp, event_id, "Network activity", "ip-src", source_ip, "Attacker IP Address")
            add_attribute(misp, event_id, "Network activity", "domain", domain_name, "Attacker Domain") if domain_name else None
            add_attribute(misp, event_id, "Network activity", "ip-dst", target_ip, "Target IP Address")
            add_attribute(misp, event_id, "Network activity", "url", target_url, "Target URL") if target_url else None
            add_attribute(misp, event_id, "Other", "text", service, "Targeted Service")
            add_attribute(misp, event_id, "Other", "datetime", attack_datetime, "Attack Date & Time") if attack_datetime else None
            if description:
                add_attribute(misp, event_id, category="Other",  attr_type="text", value=description, comment="Incident Description")
            if attack_type:
                add_attribute(misp, event_id, category="Other", attr_type="text", value=attack_type,
                              comment="attack method")

            # Upload log file to MISP
            if log_file and allowed_log_file(log_file.filename):
                upload_log_to_misp(misp, event_id, log_file, "External analysis", "attachment", "Log file of attack")

            flash(
                '✅ Report submitted successfully - Thank you!',
                'light')
            return redirect(url_for('password_attack.password_attack'))

        except Exception as e:
            flash(f"An error occurred: {e}", "danger")
            return redirect(url_for('password_attack.password_attack'))

    return render_template('password_attack.html', available_organisations=available_organisations, today_date=datetime.today().strftime('%Y-%m-%d'))


def add_attribute(misp, event_id, category, attr_type, value, comment=None):
    """Helper function to add an attribute to a MISP event."""
    if value:
        misp.add_attribute(event_id, {
            "category": category,
            "type": attr_type,
            "value": value,
            "comment": comment
        })


def upload_log_to_misp(misp, event_id, file, category, attr_type, comment):
    """Uploads the log file as an attachment to MISP without processing it."""
    filename = secure_filename(file.filename)
    encoded_data = base64.b64encode(file.read()).decode('utf-8')

    misp.add_attribute(event_id, {
        "category": category,
        "type": attr_type,
        "value": filename,
        "data": encoded_data,
        "comment": f"{comment} - Uploaded File"
    })


def allowed_log_file(filename):
    """Check if the uploaded log file has a valid extension."""
    allowed_extensions = {'log', 'txt'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions
