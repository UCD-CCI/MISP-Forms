import os
import email
import base64
import re
import quopri
import chardet
from bs4 import BeautifulSoup
from flask import Blueprint, render_template, request, flash, redirect, url_for
from pymisp import MISPEvent, MISPObject, ExpandedPyMISP, MISPAttribute
from email.header import decode_header
from email.utils import parseaddr
from misp_connect import get_api_key_for_org, get_available_organisations

upload_eml_bp = Blueprint('upload_eml', __name__, template_folder='../templates')

@upload_eml_bp.route('/upload_eml', methods=['GET', 'POST'])
def upload_eml():
    available_organisations = get_available_organisations()

    if request.method == 'POST':
        selected_org = request.form.get('organisation')
        MISP_API_KEY = get_api_key_for_org(selected_org)

        if not MISP_API_KEY:
            flash("Invalid organisation selected. Please try again.", "danger")
            return redirect(url_for('upload_eml.upload_eml'))

        if 'eml_file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)

        file = request.files['eml_file']

        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)

        if file and file.filename.endswith('.eml'):
            filepath = os.path.join('/tmp', file.filename)
            file.save(filepath)

            try:
                create_misp_event(filepath, MISP_API_KEY, selected_org)
                flash(
                    '✅ Report submitted successfully - Thank you!',
                    'light')

            except Exception as e:
                flash(f'Failed to process EML file: {str(e)}', 'danger')

            os.remove(filepath)
            return redirect(url_for('upload_eml.upload_eml'))

        flash('Invalid file type, please upload a .eml file', 'danger')
        return redirect(request.url)

    return render_template('upload_eml.html', available_organisations=available_organisations)

def create_misp_event(filepath, api_key, organisation):
    import re

    def clean_subject(subject):
        # MISP does not support emoji in info field, so stripping out these characters.
        emoji_pattern = re.compile(
            "[" 
            "\U0001F600-\U0001F64F"  # emoticons
            "\U0001F300-\U0001F5FF"  # symbols & pictographs
            "\U0001F680-\U0001F6FF"  # transport & map symbols
            "\U0001F1E0-\U0001F1FF"  # flags
            "\U00002700-\U000027BF"  # dingbats
            "\U000024C2-\U0001F251"  # enclosed characters
            "]+", flags=re.UNICODE
        )
        clean = emoji_pattern.sub('', subject)
        return clean.encode('ascii', 'ignore').decode('ascii').strip()

    MISP_URL = os.getenv('MISP_URL')
    MISP_VERIFY_SSL = os.getenv('MISP_VERIFY_SSL', 'False').lower() == 'true'
    misp = ExpandedPyMISP(MISP_URL, api_key, MISP_VERIFY_SSL)

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as eml_file:
        msg = email.message_from_file(eml_file)

    raw_subject = msg.get('Subject', '').strip()
    decoded_subject_raw = extract_decoded_header(raw_subject) if raw_subject else '(No Subject)'
    decoded_subject = clean_subject(decoded_subject_raw)

    misp_event = MISPEvent()
    misp_event.info = f"Phishing Email - {decoded_subject[:180]}"
    misp_event.distribution = 0
    misp_event.threat_level_id = 4
    misp_event.analysis = 0

    # Add Tags
    tags = [
        'rsit:fraud="phishing"',
        'circl: incident - classification = "phishing"',
        'tlp:red',
        'source:UnderServed',
        'source:MISP-Forms',
        'misp-galaxy:mitre-attack-pattern="Phishing - T1660"',
        'misp-galaxy:mitre-attack-pattern="Phishing for Information - T1598"'
    ]
    for tag in tags:
        misp_event.add_tag(tag)

    event = misp.add_event(misp_event)
    event_id = event['Event']['id']

    email_object = MISPObject('email')
    email_object.add_attribute('from', value=parseaddr(msg.get('From', ''))[1], type='email-src')
    email_object.add_attribute('to', value=parseaddr(msg.get('To', ''))[1], type='email-dst')
    email_object.add_attribute('subject', value=decoded_subject_raw, type='text')
    email_object.add_attribute('send-date', value=msg.get('Date', ''), type='datetime')

    if msg.get('Message-ID'):
        email_object.add_attribute('message-id', value=msg['Message-ID'], type='text')

    if msg.get('Reply-To'):
        email_object.add_attribute('reply-to', value=parseaddr(msg['Reply-To'])[1], type='email-reply-to')

    # Extract IP addresses from Received headers
    received_headers = msg.get_all("Received", [])
    for received in received_headers:
        ip_matches = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', received)  #review regex
        for ip in ip_matches:
            ip_attribute = MISPAttribute()
            ip_attribute.type = "ip-src"
            ip_attribute.value = ip.strip()
            ip_attribute.comment = "Extracted from Received headers"
            ip_attribute.category = "Network activity"
            misp.add_attribute(event_id, ip_attribute)

    urls = set()
    plain_text_body = ""
    html_text_body = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition"))

            if content_type == 'text/plain' and 'attachment' not in disposition:
                plain_text_body += extract_text_payload(part) or ""

            elif content_type == 'text/html' and 'attachment' not in disposition:
                html_text_body += extract_text_payload(part) or ""
                soup = BeautifulSoup(html_text_body, 'html.parser')
                for a_tag in soup.find_all('a', href=True):
                    urls.add(a_tag['href'])

            elif part.get_filename():  # Handle attachments
                filename = part.get_filename()
                payload = part.get_payload(decode=True)
                if payload:
                    encoded_payload = base64.b64encode(payload).decode('utf-8')
                    file_object = MISPObject('file')
                    file_object.add_attribute('filename', value=filename)
                    file_object.add_attribute('attachment', data=encoded_payload, value=filename)
                    misp.add_object(event_id, file_object)
    else:
        plain_text_body = extract_text_payload(msg) or ""

    if plain_text_body.strip():
        plain_attr = MISPAttribute()
        plain_attr.type = "text"
        plain_attr.value = plain_text_body
        plain_attr.comment = "Extracted plain text email body"
        plain_attr.category = "External analysis"
        misp.add_attribute(event_id, plain_attr)
        urls.update(re.findall(r'https?://[\w./?&=%-]+', plain_text_body))

    if html_text_body.strip():
        readable_text = html_to_text(html_text_body)
        html_attr = MISPAttribute()
        html_attr.type = "text"
        html_attr.value = readable_text
        html_attr.comment = "Converted HTML body to plain text"
        html_attr.category = "External analysis"
        misp.add_attribute(event_id, html_attr)

    for url in urls:
        url_clean = url.strip()
        if url_clean.startswith(('http://', 'https://')):
            url_attribute = MISPAttribute()
            url_attribute.type = "url"
            url_attribute.value = url_clean
            url_attribute.category = "Network activity"
            misp.add_attribute(event_id, url_attribute)

    misp.add_object(event_id, email_object)


#Decode email headers that may be encoded in different charsets.
def extract_decoded_header(header):
    if header:
        decoded_parts = decode_header(header)
        return ' '.join(str(part[0], part[1] or 'utf-8') if isinstance(part[0], bytes) else part[0] for part in decoded_parts)
    return None

# Extract and decode the text payload from an email part
def extract_text_payload(part):
    payload = part.get_payload(decode=True)
    if not payload:
        return None

    charset = part.get_content_charset()
    if charset:
        try:
            return payload.decode(charset, errors='ignore')
        except Exception:
            pass

    detected = chardet.detect(payload)
    if detected['confidence'] > 0.5:
        try:
            return payload.decode(detected['encoding'], errors='ignore')
        except Exception:
            pass

    try:
        return quopri.decodestring(payload).decode('utf-8', errors='ignore')
    except Exception:
        return payload.decode(errors='ignore')


# Convert HTML to readable plain text.
def html_to_text(html):
    soup = BeautifulSoup(html, 'html.parser')
    return soup.get_text(separator='\n').strip()
