import os
from flask import Blueprint, render_template, request, redirect, url_for, flash
from pymisp import PyMISP, MISPEvent, MISPAttribute
from misp_connect import get_api_key_for_org, get_available_organisations  # Import from misp_connect
from datetime import datetime


invoice_bp = Blueprint('invoice', __name__, template_folder='../templates')

@invoice_bp.route('/invoice_diversion', methods=['GET', 'POST'])
def invoice_diversion():
    available_organisations = get_available_organisations()

    if request.method == 'POST':
        try:
            selected_org = request.form.get('organisation')
            MISP_API_KEY = get_api_key_for_org(selected_org)

            if not MISP_API_KEY:
                flash("Invalid organisation selected. Please try again.", "danger")
                return redirect(url_for('invoice.invoice_diversion'))

            MISP_URL = os.getenv('MISP_URL')
            MISP_VERIFY_SSL = os.getenv('MISP_VERIFY_SSL', 'False').lower() == 'true'
            misp = PyMISP(MISP_URL, MISP_API_KEY, MISP_VERIFY_SSL)

            # Collect form data
            victim_email = request.form.get('victim_email')
            attacker_email = request.form.get('attacker_email')
            bank_account = request.form.get('bank_account')
            payment_reference = request.form.get('payment_reference')
            narrative = request.form.get('narrative')
            date = request.form.get('date', datetime.today().strftime('%Y-%m-%d'))
            time = request.form.get('time')

            distribution = int(request.form.get('distribution', 0))
            threat_level_id = int(request.form.get('threat_level_id', 4))
            analysis = int(request.form.get('analysis', 0))
            tlp = request.form.get('tlp')

            # Create MISP event
            misp_event = MISPEvent()
            misp_event.info = f"Invoice Diversion Fraud Report - {attacker_email})"
            misp_event.distribution = distribution
            misp_event.threat_level_id = threat_level_id
            misp_event.analysis = analysis
            misp_event.add_tag('rsit:fraud="phishing"')
            misp_event.add_tag('rsit:fraud="masquerade"')
            misp_event.add_tag('source:UnderServed')
            misp_event.add_tag('source:MISP-Forms')
            misp_event.add_tag('rsit:information-gathering="social-engineering"')
            misp_event.add_tag('circl:incident-classification="scam"')
            misp_event.add_tag('circl:topic="finance"')
            misp_event.add_tag('misp-galaxy:mitre-attack-pattern="Financial Theft - T1657"')  # invoice fraud
            misp_event.add_tag('misp-galaxy:mitre-attack-pattern="Impersonation - T1656"')  # invoice fraud
            date = request.form.get('date', datetime.today().strftime('%Y-%m-%d'))
            time = request.form.get('time')

            if tlp:
                misp_event.add_tag(tlp)

            event = misp.add_event(misp_event)
            event_id = event['Event']['id']

            # Add attributes
            add_attribute(misp, event_id, category="Payload delivery",  type="email-src", value=attacker_email, comment="Attacker Email Address")
            add_attribute(misp, event_id, category="Payload delivery",  type="email-dst", value=victim_email, comment="Victim Email Address")
            if bank_account:
                add_attribute(misp, event_id, category="Financial fraud",  type="iban", value=bank_account, comment="Fraudulent Bank Account")
            if payment_reference:
                add_attribute(misp, event_id, category="Financial fraud",  type="text", value=payment_reference, comment="Payment Reference")
            if narrative:
                add_attribute(misp, event_id, category="Other",  type="text", value=narrative, comment="Description of the fraud")
            if time:
                add_attribute(misp, event_id, category="Other",  type="datetime", value=f"{date} {time}",
                              comment="Date and Time of Attack")

            flash(
                '✅ Report submitted successfully - Thank you!',
                'light')
            return redirect(url_for('invoice.invoice_diversion'))

        except Exception as e:
            flash(f"An error occurred: {e}", "danger")
            return redirect(url_for('invoice.invoice_diversion'))

    return render_template('invoice_diversion.html', available_organisations=available_organisations,today_date=datetime.today().strftime('%Y-%m-%d'))


def add_attribute(misp, event_id, category,  type, value, comment=None):
    attribute = MISPAttribute()
    attribute.category = category
    attribute.type =  type
    attribute.value = value
    if comment:
        attribute.comment = comment
    response = misp.add_attribute(event_id, attribute)
    return response
