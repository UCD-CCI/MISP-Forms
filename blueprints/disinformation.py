import os
from flask import Blueprint, render_template, request, redirect, url_for, flash
from pymisp import PyMISP, MISPEvent, MISPAttribute
from datetime import datetime
from misp_connect import get_api_key_for_org, get_available_organisations  # Import from misp_connect

disinformation_bp = Blueprint('disinformation', __name__, template_folder='../templates')

@disinformation_bp.route('/disinformation', methods=['GET', 'POST'])
def disinformation():
    available_organisations = get_available_organisations()

    if request.method == 'POST':
        try:
            selected_org = request.form.get('organisation')
            MISP_API_KEY = get_api_key_for_org(selected_org)

            if not MISP_API_KEY:
                flash("Invalid organisation selected. Please try again.", "danger")
                return redirect(url_for('disinformation.disinformation'))

            MISP_URL = os.getenv('MISP_URL')
            MISP_VERIFY_SSL = os.getenv('MISP_VERIFY_SSL', 'False').lower() == 'true'
            misp = PyMISP(MISP_URL, MISP_API_KEY, MISP_VERIFY_SSL)

            # Collect form data
            url = request.form.get('url')
            narrative = request.form.get('narrative')
            timestamp = request.form.get('timestamp')
            threat_actor = request.form.get('threat_actor')

            distribution = int(request.form.get('distribution', 0))
            threat_level_id = int(request.form.get('threat_level_id', 4))
            analysis = int(request.form.get('analysis', 0))
            tlp = request.form.get('tlp')
            date = request.form.get('date', datetime.today().strftime('%Y-%m-%d'))
            time = request.form.get('time')

            if not url or not narrative:
                flash("Both URL and Narrative are required fields.", "danger")
                return redirect(url_for('disinformation.disinformation'))

            # Create MISP event
            misp_event = MISPEvent()
            misp_event.info = f"Disinformation Report - {url})"
            misp_event.distribution = distribution
            misp_event.threat_level_id = threat_level_id
            misp_event.analysis = analysis

            misp_event.add_tag("type:disinformation")
            misp_event.add_tag("Disinformation")
            misp_event.add_tag("Social Media")
            misp_event.add_tag("Misinformation Campaign")
            if tlp:
                misp_event.add_tag(tlp)

            event = misp.add_event(misp_event)
            event_id = event['Event']['id']

            add_attribute(misp, event_id, category="Network activity",  type="url", value=url, comment="Source of disinformation")
            if time:
                add_attribute(misp, event_id, category="Other",  type="datetime", value=f"{date} {time}",
                              comment="Date and Time of Attack")
            add_attribute(misp, event_id, category="Other",  type="text", value=narrative, comment="Disinformation narrative")
            if timestamp:
                add_attribute(misp, event_id, category="Network activity",  type="timestamp", value=timestamp, comment="Observation time")
            if threat_actor:
                add_attribute(misp, event_id, category="Attribution",  type="threat-actor", value=threat_actor, comment="Suspected actor")





            flash(
                '✅ Report submitted successfully - Thank you!',
                'light')
            return redirect(url_for('disinformation.disinformation'))

        except Exception as e:
            flash(f"An error occurred: {e}", "danger")
            return redirect(url_for('disinformation.disinformation'))

    return render_template('disinformation.html', available_organisations=available_organisations,today_date=datetime.today().strftime('%Y-%m-%d'))


def add_attribute(misp, event_id, category,  type, value, comment=None):
    attribute = MISPAttribute()
    attribute.category = category
    attribute.type =  type
    attribute.value = value
    if comment:
        attribute.comment = comment
    response = misp.add_attribute(event_id, attribute)
    return response
