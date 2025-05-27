import base64
import os
import hashlib
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
from pymisp import ExpandedPyMISP, MISPEvent, MISPAttribute
from misp_connect import get_api_key_for_org, get_available_organisations

social_eng_bp = Blueprint('social_eng', __name__, template_folder='../templates')

@social_eng_bp.route('/social_eng', methods=['GET', 'POST'])
def social_eng():
    available_organisations = get_available_organisations()

    if request.method == 'POST':
        try:
            selected_org = request.form.get('organisation')
            MISP_API_KEY = get_api_key_for_org(selected_org)

            if not MISP_API_KEY:
                flash("Invalid organisation selected. Please try again.", "danger")
                return redirect(url_for('social_eng.social_eng'))

            MISP_URL = os.getenv('MISP_URL')
            MISP_VERIFY_SSL = os.getenv('MISP_VERIFY_SSL', 'False').lower() == 'true'

            misp = ExpandedPyMISP(MISP_URL, MISP_API_KEY, MISP_VERIFY_SSL)

            attack_type = request.form.get('attack_type')
            attacker_email = request.form.get('attacker_email')
            attacker_phone = request.form.get('attacker_phone')
            attacker_name = request.form.get('attacker_name')
            victim_org = request.form.get('victim_org')
            targeted_department = request.form.get('targeted_department')
            description = request.form.get('description')
            date = request.form.get('date', datetime.today().strftime('%Y-%m-%d'))
            time = request.form.get('time')
            attack_evidence = request.files.get('attack_evidence')
            tlp = request.form.get('tlp')

            print("Form Data Submitted:", request.form.to_dict())

            distribution = int(request.form.get('distribution', 0))
            threat_level_id = int(request.form.get('threat_level_id', 4))  # Default: Undefined
            analysis = int(request.form.get('analysis', 2))  # Default: Completed

            # Create the MISP event
            misp_event = MISPEvent()
            misp_event.info = f"Social Engineering Attack - {attack_type}"
            misp_event.date = date
            misp_event.distribution = distribution
            misp_event.threat_level_id = threat_level_id
            misp_event.analysis = analysis
            misp_event.add_tag('circl:incident-classification="social-engineering"')
            misp_event.add_tag('misp-galaxy:mitre-attack-pattern="Conduct social engineering - T1279"')  # social engineering
            misp_event.add_tag('source:UnderServed')
            misp_event.add_tag('source:MISP-Forms')
            misp_event.add_tag(f"attack-type:{attack_type.lower()}")
            if tlp:
                misp_event.add_tag(tlp)

            event = misp.add_event(misp_event)
            if 'Event' not in event:
                flash("Error: MISP event creation failed!", "danger")
                return redirect(url_for('social_eng.social_eng'))

            event_id = event['Event']['id']
            print(f"MISP Event Created: {event_id}")

            # Add attributes
            add_attribute(misp, event_id, category="Other", attr_type="text", value=attack_type, comment="Type of Social Engineering Attack")
            add_attribute(misp, event_id, category="Targeting data", attr_type="text", value=victim_org, comment="Victim Organisation")
            if targeted_department:
                add_attribute(misp, event_id, category="Targeting data", attr_type="text", value=targeted_department, comment="Targeted Department")
            if attacker_email:
                add_attribute(misp, event_id, category="Attribution", attr_type="email-src", value=attacker_email, comment="Attacker Email")
            if attacker_phone:
                add_attribute(misp, event_id, category="Attribution", attr_type="phone-number", value=attacker_phone, comment="Attacker Phone Number")
            if attacker_name:
                add_attribute(misp, event_id, category="Attribution", attr_type="text", value=attacker_name, comment="Attacker Name or Alias")
            if description:
                add_attribute(misp, event_id, category="External analysis", attr_type="text", value=description, comment="Description of Attack")
            if time:
                add_attribute(misp, event_id, category="Other", attr_type="datetime", value=f"{date} {time}", comment="Date and Time of Attack")

            if attack_evidence and allowed_evidence_file(attack_evidence.filename):
                process_uploaded_file(misp, event_id, attack_evidence, category="External analysis", attr_type="attachment", comment="Social Engineering Attack Evidence")

            flash(
                '✅ Report submitted successfully - Thank you!',
                'light')
            return redirect(url_for('social_eng.social_eng'))

        except Exception as e:
            flash(f"An error occurred: {e}", "danger")
            return redirect(url_for('social_eng.social_eng'))

    return render_template('social_eng.html', available_organisations=available_organisations, today_date=datetime.today().strftime('%Y-%m-%d'))


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
    print(f"Added Attribute: {attr_type}, Response: {response}")
    return response


def process_uploaded_file(misp, event_id, file, category, attr_type, comment):
    filename = secure_filename(file.filename)
    file_content = file.read()

    encoded_data = base64.b64encode(file_content).decode('utf-8')

    add_attribute(misp, event_id, category, attr_type="attachment", value=filename, data=encoded_data, comment=f"{comment} Uploaded")


def allowed_evidence_file(filename):
    allowed_extensions = {'png', 'jpg', 'jpeg', 'pdf', 'mp3', 'wav'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions
