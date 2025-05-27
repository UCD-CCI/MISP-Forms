import logging
from flask import Blueprint, render_template, request, flash, redirect, current_app, url_for
import os
import re
from werkzeug.utils import secure_filename
from PIL import Image
import pytesseract
from dotenv import load_dotenv
from pylookyloo import Lookyloo

load_dotenv()

# Initialise Lookyloo (this is lookyloo instance running on underserved platform
lookyloo_url = os.getenv('LOOKYLOO_URL')
lookyloo = Lookyloo(lookyloo_url)
lookyloo.session.verify = False


smishing_bp = Blueprint('smishing', __name__, template_folder='../templates')

# Reconstruct broken URLs
def reconstruct_broken_urls(text):
    logging.debug("Reconstructing broken URLs from extracted text.")
    lines = text.splitlines()
    reconstructed_text = []
    temp_line = ""

    for line in lines:
        line = line.strip()
        if temp_line:
            if re.match(r'^[\w\-\.=&:/?#\[\]@!$\'()*+,;]+', line):  # Starts with a word or special character
                temp_line += line
                continue
            else:
                reconstructed_text.append(temp_line)
                temp_line = ""

        if '://' in line or 'www.' in line:
            temp_line = line
        else:
            reconstructed_text.append(line)

    if temp_line:
        reconstructed_text.append(temp_line)

    logging.debug(f"Reconstructed text: {reconstructed_text}")
    return "\n".join(reconstructed_text)


# Correct OCR-related mistakes in URLs
def correct_urls(urls):
    logging.debug(f"Correcting extracted URLs: {urls}")
    corrections = {
        r'\bhttpo://': 'http://',
        r'\bhttpos://': 'https://',
        r'\bhitps://': 'https://',
        r'\bhitp://': 'http://',
        r'\blttps://': 'https://',
        r'\blttp://': 'http://',
        r'\bhtp://': 'http://',
        r'\bhitos://': 'https://',
        r'\b]': '',
        r'\+': '',
        r'\[': '/'
                   }
    corrected_urls = []
    for url in urls:
        for pattern, replacement in corrections.items():
            url = re.sub(pattern, replacement, url)
        corrected_urls.append(url)

    logging.debug(f"Corrected URLs: {corrected_urls}")
    return corrected_urls


# Extract URLs from text
def extract_details(text):
    logging.debug("Extracting details from text.")
    cleaned_text = reconstruct_broken_urls(text)
    url_regex = r'\b(?:[a-zA-Z][a-zA-Z0-9+.-]*://|www\.|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,3}(?:\b|/))[^\s<>"]*'
    urls = re.findall(url_regex, cleaned_text)
    corrected_urls = correct_urls(urls)
    logging.debug(f"Extracted URLs: {corrected_urls}")
    return {'urls': corrected_urls}


@smishing_bp.route('/smishing', methods=['GET', 'POST'])
def smishing():
    logging.info("Processing /smishing route.")
    extracted_text = None
    details = None
    uploaded_image = None

    if request.method == 'POST':
        manual_url = request.form.get('manual_url')
        if manual_url:
            logging.debug(f"Manual URL submitted: {manual_url}")
            if lookyloo.is_up:
                try:
                    lookyloo_url = lookyloo.enqueue(manual_url)
                    logging.info(f"URL successfully enqueued in Lookyloo: {lookyloo_url}")
                    return redirect(lookyloo_url)  # Redirect to Lookyloo's page for the URL
                except Exception as e:
                    logging.error(f"Error with Lookyloo: {e}")
            else:
                logging.warning("Lookyloo instance is not reachable.")
            return redirect(url_for('smishing.smishing'))  # Redirect back to the form if an error occurs

        # uploaded image
        if 'image' in request.files:
            file = request.files['image']
            logging.debug(f"Uploaded file: {file.filename}")
            if file.filename == '':
                flash('No selected file', 'error')
                return render_template('smishing.html', text=extracted_text, details=details, uploaded_image=uploaded_image)

            if file:
                filename = secure_filename(file.filename)
                upload_folder = current_app.config.get('UPLOAD_FOLDER', 'static/uploads')
                os.makedirs(upload_folder, exist_ok=True)
                filepath = os.path.join(upload_folder, filename)
                file.save(filepath)

                uploaded_image = url_for('static', filename=f'uploads/{filename}')
                logging.info(f"File saved at: {filepath}")

                try:
                    image = Image.open(filepath)
                    extracted_text = pytesseract.image_to_string(image, config='--psm 6')
                    details = extract_details(extracted_text)

                    if details.get('urls'):
                        logging.info(f"Extracted URLs: {details['urls']}")

                    else:
                        logging.info("No URLs extracted.")

                except Exception as e:
                    logging.error(f"Error processing file: {e}")

    return render_template(
        'smishing.html',
        text=extracted_text,
        details=details,
        uploaded_image=uploaded_image,
    )


@smishing_bp.route('/analyse_url', methods=['POST'])
def analyse_url():
    logging.info("Processing /analyse_url route.")
    url_to_analyse = request.form.get('analyse_url')
    logging.debug(f"URL to analyze: {url_to_analyse}")

    if not url_to_analyse:
        logging.error("No URL provided for analysis.")
        flash("No URL provided for analysis.", "error")
        return redirect(url_for('smishing.smishing'))

    if lookyloo.is_up:
        try:
            lookyloo_url = lookyloo.enqueue(url_to_analyse)
            logging.info(f"URL successfully enqueued in Lookyloo: {lookyloo_url}")
            return redirect(lookyloo_url)
        except Exception as e:
            logging.error(f"Error with Lookyloo: {e}")
            flash(f"An error occurred with Lookyloo: {e}", "error")
    else:
        logging.warning("Lookyloo instance is not reachable.")
        flash("Lookyloo instance is not reachable.", "error")

    return redirect(url_for('smishing.smishing'))
