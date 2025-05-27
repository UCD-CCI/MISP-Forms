import os
import logging
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash
from pymisp import ExpandedPyMISP, MISPEvent, MISPAttribute
from misp_connect import get_api_key_for_org, get_available_organisations

vishing_bp = Blueprint('vishing', __name__, template_folder='../templates')

@vishing_bp.route('/vishing', methods=['GET', 'POST'])
def vishing():
    available_organisations = get_available_organisations()

    if request.method == 'POST':
        try:
            selected_org = request.form.get('organisation')
            MISP_API_KEY = get_api_key_for_org(selected_org)

            if not MISP_API_KEY:
                flash("Invalid organisation selected. Please try again.", "danger")
                return redirect(url_for('vishing.vishing'))

            MISP_URL = os.getenv('MISP_URL')
            MISP_VERIFY_SSL = os.getenv('MISP_VERIFY_SSL', 'False').lower() == 'true'

            misp = ExpandedPyMISP(MISP_URL, MISP_API_KEY, MISP_VERIFY_SSL)

            # Collect form data
            caller_phone = request.form.get('caller_phone')

            full_message = request.form.get('full_message')
            callback_number = request.form.get('callback_number')

            date = request.form.get('date', datetime.today().strftime('%Y-%m-%d'))
            time = request.form.get('time')
            distribution = int(request.form.get('distribution', 0))
            threat_level_id = int(request.form.get('threat_level_id', 4))
            analysis = int(request.form.get('analysis', 2))

            if not caller_phone or not full_message:
                flash('Caller Phone Number and Full Message are required fields.', 'danger')
                return redirect(url_for('vishing.vishing'))

            # Create the MISP event
            misp_event = MISPEvent()
            misp_event.info = "Vishing (Voice Phishing) Attack Report"

            tlp = request.form.get('tlp')
            misp_event.add_tag('circl:incident-classification="social-engineering"')
            misp_event.add_tag('rsit:information-gathering="social-engineering"')
            misp_event.add_tag('misp-galaxy:mitre-attack-pattern="Conduct social engineering - T1279"')  # social engineering
            misp_event.add_tag('misp-galaxy:financial-fraud="Vishing"')  # vishing
            misp_event.add_tag('source:UnderServed')
            misp_event.add_tag('source:MISP-Forms')
            misp_event.distribution = distribution
            misp_event.threat_level_id = threat_level_id
            misp_event.analysis = analysis

            if tlp:
                misp_event.add_tag(tlp)

            event = misp.add_event(misp_event)
            if 'Event' not in event:
                flash("Error: MISP event creation failed!", "danger")
                return redirect(url_for('vishing.vishing'))



            event_id = event['Event']['id']

            # Add attributes
            add_attribute(misp, event_id, category="Financial fraud",  type="phone-number", value=caller_phone, comment="Caller Phone Number (Attacker)")
            add_attribute(misp, event_id, category="Payload delivery",  type="text", value=full_message, comment="Full Vishing Message Content")
            if callback_number:
                add_attribute(misp, event_id, category="Financial fraud",  type="phone-number", value=callback_number, comment="Callback Number Provided by Attacker")
            if time:
                add_attribute(misp, event_id, category="Other",  type="datetime", value=f"{date} {time}", comment="Date and Time of Attack")

            flash(
                '✅ Report submitted successfully - Thank you!',
                'light')
            return redirect(url_for('vishing.vishing'))

        except Exception as e:
            flash(f"An error occurred: {e}", "danger")

    return render_template('vishing.html', available_organisations=available_organisations, today_date=datetime.today().strftime('%Y-%m-%d'))


def add_attribute(misp, event_id, category,  type, value, comment=None):
    attribute = MISPAttribute()
    attribute.category = category
    attribute.type =  type
    attribute.value = value
    if comment:
        attribute.comment = comment
    misp.add_attribute(event_id, attribute)
