import os
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash
from pymisp import PyMISP, MISPEvent, MISPAttribute
from misp_connect import get_api_key_for_org, get_available_organisations

ddos_bp = Blueprint('ddos', __name__, template_folder='templates')

@ddos_bp.route('/ddos', methods=['GET', 'POST'])
def ddos():
    MISP_URL = os.getenv('MISP_URL')
    MISP_VERIFY_SSL = os.getenv('MISP_VERIFY_SSL', 'False').lower() == 'true'
    available_organisations = get_available_organisations()  # Get list dynamically


    if request.method == 'POST':
        selected_org = request.form.get('organisation')
        MISP_API_KEY = get_api_key_for_org(selected_org)

        if not MISP_API_KEY:
            flash("Invalid organisation selected. Please try again.", "danger")
            return redirect(url_for('ddos.ddos'))

        misp = PyMISP(MISP_URL, MISP_API_KEY, MISP_VERIFY_SSL)

        try:
            # Collect form data
            source_ips = request.form.get('source_ip', '').split(',')
            target_ip = request.form.get('target_ip')
            target_url = request.form.get('target_url')
            port = request.form.get('port')
            duration = request.form.get('duration')
            protocol = request.form.get('protocol')
            attack_type = request.form.get('attack_type')
            description = request.form.get('description')
            threat_actor = request.form.get('threat_actor')
            date = request.form.get('date', datetime.today().strftime('%Y-%m-%d'))
            time = request.form.get('time')
            tlp = request.form.get('tlp')

            distribution = int(request.form.get('distribution', 0))
            threat_level_id = int(request.form.get('threat_level_id', 4))
            analysis = int(request.form.get('analysis', 0))

            if not target_ip and not target_url:
                flash("Either a target IP or target URL must be provided.", "danger")
                return redirect(url_for('ddos.ddos'))


            # Create MISP event
            misp_event = MISPEvent()
            misp_event.info = f"DDoS Attack Report - {target_ip or target_url}"
            misp_event.distribution = distribution
            misp_event.threat_level_id = threat_level_id
            misp_event.analysis = analysis

            if tlp:
                misp_event.add_tag(tlp)

            misp_event.add_tag('rsit:availability="ddos"')
            misp_event.add_tag('rsit:availability="dos"')
            misp_event.add_tag('circl:incident-classification="denial-of-service"')            
            misp_event.add_tag('source:UnderServed')
            misp_event.add_tag('source:MISP-Forms')
            misp_event.add_tag('misp-galaxy:mitre-attack-pattern="Network Denial of Service - T1498"')  # ddos

            event = misp.add_event(misp_event)
            event_id = event['Event']['id']

            # Add attributes
            for ip in source_ips:
                ip = ip.strip()
                if ip:
                    add_attribute(misp, event_id, category="Network activity", type="ip-src", value=ip)

            if target_ip:
                add_attribute(misp, event_id, category="Network activity", type="ip-dst", value=target_ip)
            if target_url:
                add_attribute(misp, event_id, category="Network activity", type="domain", value=target_url)
            if port:
                add_attribute(misp, event_id, category="Network activity", type="dst-port", value=port)
            if duration:
                add_attribute(misp, event_id, category="Other", type="text", value=f"{duration} minutes", comment="Duration of the attack")
            if protocol: ## not an MISP atribute - find alternative
                add_attribute(misp, event_id, category="Network activity", type="protocol", value=protocol)
            if attack_type:
                add_attribute(misp, event_id, category="Network activity", type="pattern-in-traffic", value=attack_type, comment="Attack Type")
            if description:
                add_attribute(misp, event_id, category="Other", type="text", value=description, comment="Description of Event")
            if threat_actor:
                add_attribute(misp, event_id, category="Attribution", type="threat-actor", value=threat_actor)
            if time:
                add_attribute(misp, event_id, category="Other", type="datetime", value=f"{date} {time}",
                              comment="Date and Time of Attack")

            flash(
                '✅ Report submitted successfully - Thank you!',
                'light')
            #
            return redirect(url_for('ddos.ddos'))
        except Exception as e:
            flash(f"An error occurred: {e}", "danger")
            return redirect(url_for('ddos.ddos'))

    return render_template('ddos.html', available_organisations=available_organisations, today_date=datetime.today().strftime('%Y-%m-%d'))


def add_attribute(misp, event_id, category, type, value, comment=None):
    attribute = MISPAttribute()
    attribute.category = category
    attribute.type = type
    attribute.value = value
    if comment:
        attribute.comment = comment
    misp.add_attribute(event_id, attribute)
