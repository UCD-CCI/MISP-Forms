import os
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash
from pymisp import PyMISP, MISPEvent, MISPAttribute
from misp_connect import get_api_key_for_org, get_available_organisations  # Import from misp_connect

sql_injection_bp = Blueprint('sql_injection', __name__, template_folder='../templates')

@sql_injection_bp.route('/sql_injection', methods=['GET', 'POST'])
def sql_injection():
    available_organisations = get_available_organisations()

    if request.method == 'POST':
        try:
            selected_org = request.form.get('organisation')
            MISP_API_KEY = get_api_key_for_org(selected_org)

            if not MISP_API_KEY:
                flash("Invalid organisation selected. Please try again.", "danger")
                return redirect(url_for('sql_injection.sql_injection'))

            MISP_URL = os.getenv('MISP_URL')
            MISP_VERIFY_SSL = os.getenv('MISP_VERIFY_SSL', 'False').lower() == 'true'
            misp = PyMISP(MISP_URL, MISP_API_KEY, MISP_VERIFY_SSL)

            # Collect form data
            target_url = request.form.get('target_url')
            affected_database = request.form.get('affected_database')
            attacker_ip = request.form.get('attacker_ip')
            payload = request.form.get('payload')
            description = request.form.get('description')
            remediation_steps = request.form.get('remediation_steps')
            date = request.form.get('date', datetime.today().strftime('%Y-%m-%d'))
            time = request.form.get('time')
            threat_actor = request.form.get('threat_actor')
            vulnerability = request.form.get('vulnerability')
            tlp = request.form.get('tlp')

            distribution = int(request.form.get('distribution', 0))
            threat_level_id = int(request.form.get('threat_level_id', 4))
            analysis = int(request.form.get('analysis', 2))
            tlp = request.form.get('tlp')

            # Create MISP event
            misp_event = MISPEvent()
            misp_event.info = f"SQL Injection Attack Report - {target_url}"
            misp_event.date = date
            misp_event.distribution = distribution
            misp_event.threat_level_id = threat_level_id
            misp_event.analysis = analysis
            misp_event.add_tag('circl:incident-classification="sql-injection"')
            misp_event.add_tag('circl:incident-classification="application-compromise"')
            misp_event.add_tag('source:UnderServed')
            misp_event.add_tag('source:MISP-Forms')
            misp_event.add_tag('misp-galaxy:mitre-attack-pattern="Compromise of externally facing system - T1388"')  # SQL injection


            if tlp:
                misp_event.add_tag(tlp)

            event = misp.add_event(misp_event)
            if 'Event' not in event:
                flash("Error: MISP event creation failed!", "danger")
                return redirect(url_for('sql_injection.sql_injection'))

            event_id = event['Event']['id']

            # Add attributes
            add_attribute(misp, event_id, category="Network activity",  type="url", value=target_url, comment="Target URL of SQL Injection attack")
            add_attribute(misp, event_id, category="Payload delivery",  type="text", value=payload, comment="SQL Injection Payload")

            if affected_database:
                add_attribute(misp, event_id, category="Payload delivery",  type="text", value=affected_database, comment="Affected Database")
            if attacker_ip:
                add_attribute(misp, event_id, category="Network activity",  type="ip-src", value=attacker_ip, comment="Attacker IP Address")
            if description:
                add_attribute(misp, event_id, category="Other",  type="text", value=description, comment="Incident Description")
            if remediation_steps:
                add_attribute(misp, event_id, category="Other",  type="text", value=remediation_steps, comment="Remediation Steps")
            if time:
                add_attribute(misp, event_id, category="Other",  type="datetime", value=f"{date} {time}", comment="Date and Time of Attack")
            if vulnerability:
                add_attribute(misp, event_id, category="External analysis", type="vulnerability", value=vulnerability)
            if threat_actor:
                add_attribute(misp, event_id, category="Attribution", type="threat-actor", value=threat_actor)

            flash(
                '✅ Report submitted successfully - Thank you!',
                'light')
            return redirect(url_for('sql_injection.sql_injection'))

        except Exception as e:
            flash(f"An error occurred: {e}", "danger")
            return redirect(url_for('sql_injection.sql_injection'))

    return render_template('sql_injection.html', available_organisations=available_organisations, today_date=datetime.today().strftime('%Y-%m-%d'))


def add_attribute(misp, event_id, category,  type, value, comment=None):
    attribute = MISPAttribute()
    attribute.category = category
    attribute.type =  type
    attribute.value = value
    if comment:
        attribute.comment = comment
    response = misp.add_attribute(event_id, attribute)
    return response
