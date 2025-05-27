from flask import Blueprint, render_template, request, redirect, flash
from pylookyloo import Lookyloo
from pymisp import ExpandedPyMISP, MISPEvent, MISPObject
import threading, subprocess, os, json
from dotenv import load_dotenv


load_dotenv()

# Initialise Lookyloo (this is lookyloo instance running on underserved platform
lookyloo_url = os.getenv('LOOKYLOO_URL')
lookyloo = Lookyloo(lookyloo_url)
lookyloo.session.verify = False

# MISP setup
misp_url = 'https://misp.underserved.org'
misp_key = 'misp-org1-apikey'
verify_cert = False
tld_file = './dictionaries/common_tlds.dict'
output_file = '/tmp/data.json'

typo_squatting_bp = Blueprint('typo_squatting', __name__, template_folder='../templates')

@typo_squatting_bp.route('/typo-squatting', methods=['GET', 'POST'])
def typo_squatting():
    if request.method == 'POST':
        url = request.form.get('url')
        domain = request.form.get('domain')

        if url:
            if lookyloo.is_up:
                try:
                    permaurl = lookyloo.enqueue(url)
                    return redirect(permaurl)
                except Exception as e:
                    return f"An error occurred: {e}", 500
            else:
                return "Lookyloo instance is not reachable.", 503

        if domain:
            threading.Thread(target=process_domain_task, args=(domain,)).start()
            flash( '🔍 The detection process is now running... If a potential typo-squatting site is detected, an event will be reported to <a href="https://misp.underserved.org" target="_blank">MISP</a>',
                'light')
    return render_template('typo-squatting.html')


def process_domain_task(domain):
    try:
        subprocess.run([
            "dnstwist",
            "--fuzzers", "tld-swap",
            "--tld", f"{tld_file}",
            "--lsh",
            "--format", "json", "-r", "-w", domain
        ], stdout=open(output_file, "w"), check=True)
    except subprocess.CalledProcessError:
        print("Failed to run dnstwist command.")
        return

    misp = ExpandedPyMISP(url=misp_url, key=misp_key, ssl=verify_cert)

    with open(output_file, 'r') as f:
        entries = json.load(f)

    event = MISPEvent()
    event.info = f"Potential Typo-Squatting on {domain}"
    event.distribution = 0
    event.threat_level_id = 2
    event.analysis = 0
    event.add_tag("tlp:red")
    event.add_tag('rsit:fraud="masquerade"')
    event.add_tag('type:Typo-Squatting')
    event.add_tag('source:UnderServed')
    event.add_tag('source:MISP-Forms"')


    added_domains = 0

    for entry in entries:
        if 'ssdeep' not in entry or entry['ssdeep'] <= 5:
            continue

        domain_obj = MISPObject(name='domain-ip')
        domain_obj.add_attribute('domain', type='domain', value=entry['domain'])

        for ip in entry.get('dns_a', []):
            domain_obj.add_attribute('ip', type='ip-dst', value=ip)

        for ip6 in entry.get('dns_aaaa', []):
            domain_obj.add_attribute('ip', type='ip-dst', value=ip6)

        for ns in entry.get('dns_ns', []):
            domain_obj.add_attribute('nameserver', type='hostname', value=ns)

        if 'fuzzer' in entry:
            domain_obj.add_attribute('fuzzer', type='text', value=entry['fuzzer'], comment='Fuzzing technique used')

        if 'geoip' in entry:
            domain_obj.add_attribute('geoip-location', type='text', value=entry['geoip'], comment='GeoIP resolved country')

        if 'whois_created' in entry:
            domain_obj.add_attribute('first-seen', type='datetime', value=entry['whois_created'], comment='WHOIS creation date')

        if 'whois_registrar' in entry:
            domain_obj.add_attribute('registrar', type='whois-registrar', value=entry['whois_registrar'])

        domain_obj.add_attribute('similarity-score', type='text', value=str(entry['ssdeep']), comment='SSDEEP similarity score')

        event.add_object(domain_obj)
        added_domains += 1

    if added_domains > 0:
        misp.add_event(event)
        print(f" Created MISP event with {added_domains} suspicious domains for {domain}")
    else:
        print(f" No suspicious domains (ssdeep > 5) found for {domain}")


