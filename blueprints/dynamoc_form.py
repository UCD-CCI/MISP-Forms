import os
import logging
import base64
import hashlib
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash
from pymisp import ExpandedPyMISP, MISPEvent, MISPAttribute
from werkzeug.utils import secure_filename
from misp_connect import get_api_key_for_org, get_available_organisations

dynamic_form_bp = Blueprint('dynamic_form', __name__, template_folder='../templates')

# Define MISP categories and attributes
MISP_ATTRIBUTES = {
    "Network activity": ["ip-src", "ip-dst", "url", "domain", "hostname", "user-agent"],
    "Payload delivery": ["filename", "malware-type", "email-src", "email-dst"],
    "Financial fraud": ["btc-address", "iban", "credit-card-number"],
    "Attribution": ["threat-actor", "phone-number"],
    "External analysis": ["vulnerability", "text", "attachment"],
    "Other": ["datetime"]
}

@dynamic_form_bp.route('/dynamic_form', methods=['GET', 'POST'])
def dynamic_form():
    available_organisations = get_available_organisations()

    if request.method == 'POST':
        try:
            # Get selected organisation & API key
            selected_org = request.form.get('organisation')
            MISP_API_KEY = get_api_key_for_org(selected_org)

            if not MISP_API_KEY:
                flash("Invalid organisation selected. Please try again.", "danger")
                return redirect(url_for('dynamic_form.dynamic_form'))

            MISP_URL = os.getenv('MISP_URL')
            MISP_VERIFY_SSL = os.getenv('MISP_VERIFY_SSL', 'False').lower() == 'true'

            misp = ExpandedPyMISP(MISP_URL, MISP_API_KEY, MISP_VERIFY_SSL)
            logging.info("Processing /dynamic_form route.")

            event_info = request.form.get('info')
            event_description = request.form.get('description')
            event_date = request.form.get('date', datetime.today().strftime('%Y-%m-%d'))
            event_time = request.form.get('time')
            distribution = int(request.form.get('distribution', 0))
            threat_level_id = int(request.form.get('threat_level_id', 4))
            analysis = int(request.form.get('analysis', 0))
            tlp = request.form.get('tlp')
            threat_actor = request.form.get('threat_actor')
            vulnerability = request.form.get('vulnerability')
            tags_input = request.form.get('tags')  # New input field for tags

            if not event_info or not event_description:
                flash('Event Title and Description are required fields.', 'danger')
                return redirect(url_for('dynamic_form.dynamic_form'))

            # Create MISP Event
            misp_event = MISPEvent()
            misp_event.info = event_info
            misp_event.date = event_date
            misp_event.distribution = distribution
            misp_event.threat_level_id = threat_level_id
            misp_event.analysis = analysis

            if tlp:
                misp_event.add_tag(tlp)

            if tags_input:
                tags_list = [tag.strip() for tag in tags_input.split(",") if tag.strip()]
                for tag in tags_list:
                    misp_event.add_tag(tag)

            event = misp.add_event(misp_event)
            if 'Event' not in event:
                flash("Error: MISP event creation failed!", "danger")
                return redirect(url_for('dynamic_form.dynamic_form'))

            event_id = event['Event']['id']
            logging.info(f"MISP Event Created: {event_id}")

            add_attribute(misp, event_id, category="Other", attr_type="text", value=event_info, comment="Event Title")
            add_attribute(misp, event_id, category="Other", attr_type="text", value=event_description, comment="Event Description")

            if event_time:
                add_attribute(misp, event_id, category="Other", attr_type="datetime", value=f"{event_date} {event_time}", comment="Date and Time of Event")

            if threat_actor:
                add_attribute(misp, event_id, category="Attribution", attr_type="threat-actor", value=threat_actor, comment="Threat Actor")
            if vulnerability:
                add_attribute(misp, event_id, category="External analysis", attr_type="vulnerability", value=vulnerability, comment="Related Vulnerability")

            for key in request.form.keys():
                if key.startswith('attribute_type_'):
                    index = key.split('_')[-1]
                    attr_type = request.form.get(f'attribute_type_{index}')
                    attr_value = request.form.get(f'attribute_value_{index}')
                    category = request.form.get(f'attribute_category_{index}', "Other")

                    if attr_type and attr_value:
                        add_attribute(misp, event_id, category, attr_type, attr_value)

            flash(f'Custom Report submitted successfully!', 'success')
            return redirect(url_for('dynamic_form.dynamic_form'))

        except Exception as e:
            flash(f"An error occurred: {e}", "danger")
            logging.error(f"Error in dynamic_form: {e}")
            return redirect(url_for('dynamic_form.dynamic_form'))

    return render_template('dynamic_form.html', misp_attributes=MISP_ATTRIBUTES, available_organisations=available_organisations)


def add_attribute(misp, event_id, category, attr_type, value, comment=None):
    try:
        attribute = MISPAttribute()
        attribute.category = category
        attribute.type = attr_type
        attribute.value = value
        if comment:
            attribute.comment = comment
        misp.add_attribute(event_id, attribute)
        logging.info(f"Added Attribute: {attr_type}")
    except Exception as e:
        logging.error(f"Failed to add attribute {attr_type}: {e}")
