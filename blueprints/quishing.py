from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from werkzeug.utils import secure_filename
from pyzbar.pyzbar import decode
from pylookyloo import Lookyloo
from PIL import Image, ImageEnhance
import os
import logging
import pyheif
from dotenv import load_dotenv

#logging.basicConfig(level=logging.DEBUG)

load_dotenv()

# Initialise Lookyloo (this is lookyloo instance running on underserved platform
lookyloo_url = os.getenv('LOOKYLOO_URL')
lookyloo = Lookyloo(lookyloo_url)
lookyloo.session.verify = False
quishing_bp = Blueprint('quishing', __name__, template_folder='../templates')


@quishing_bp.route('/quishing', methods=['GET', 'POST'])
def quishing():
    extracted_urls = []

    if request.method == 'POST' and 'qr_image' in request.files:
        file = request.files['qr_image']
        
        if file.filename == '':
            flash('No file selected. Please upload a QR code image.', 'error')
            return render_template('quishing.html', extracted_urls=extracted_urls)

        filename = secure_filename(file.filename)
        upload_folder = current_app.config.get('UPLOAD_FOLDER', 'uploads')
        os.makedirs(upload_folder, exist_ok=True)
        filepath = os.path.join(upload_folder, filename)
        file.save(filepath)

        # Convert HEIC to JPEG if necessary,  support pictures from mobile devices
        if file.content_type in ['image/heic', 'image/heif'] or filename.lower().endswith('.heic'):
            try:
                heif_file = pyheif.read(filepath)
                image = Image.frombytes(
                    heif_file.mode, heif_file.size, heif_file.data,
                    "raw", heif_file.mode, heif_file.stride
                )
                jpg_filepath = filepath.rsplit('.', 1)[0] + '.jpg'
                image.save(jpg_filepath, "JPEG")
                os.remove(filepath)  # Remove the original HEIC file
                filepath = jpg_filepath  # Update the path to the new JPEG file
                logging.debug("Converted HEIC image to JPEG.")
            except Exception as e:
                flash(f"Error converting HEIC image: {str(e)}", 'error')
                logging.error(f"HEIC conversion error: {str(e)}")
                return render_template('quishing.html', extracted_urls=extracted_urls)

        try:
            # Open the image and convert to grayscale
            image = Image.open(filepath)
            image = image.convert('L')  # Convert to grayscale
            logging.debug(f"Opened image: {filepath} with size {image.size} and mode {image.mode}")
            
            # Improve image clarity
            image = image.resize((image.width * 2, image.height * 2), Image.LANCZOS)  # High-quality upscaling
            
            # Apply contrast enhancement
            contrast = ImageEnhance.Contrast(image)
            image = contrast.enhance(2.0)  # Increase contrast

            # Decode QR code
            decoded_objects = decode(image)

            if not decoded_objects:
                flash("No QR code detected. Try using a higher-resolution image.", "warning")
                logging.debug("No QR code detected.")
            
            for obj in decoded_objects:
                data = obj.data.decode('utf-8')
                logging.debug(f"Decoded QR code data: {data}")
                extracted_urls.append(data)  # Store all QR code data

        except Exception as e:
            flash(f"Error processing QR code: {str(e)}", 'error')
            logging.error(f"Error processing QR code: {str(e)}")

        finally:
            if os.path.exists(filepath):
                os.remove(filepath)

    return render_template('quishing.html', extracted_urls=extracted_urls)

# Route for analysing the extracted URL with Lookyloo
@quishing_bp.route('/analyze_url', methods=['POST'])
def analyze_url():
    url_to_analyze = request.form.get('analyze_url')

    if not url_to_analyze:
        flash("No URL provided for analysis.", "error")
        return redirect(url_for('quishing.quishing'))

    if lookyloo.is_up:
        try:
            lookyloo_url = lookyloo.enqueue(url_to_analyze)
            return redirect(lookyloo_url)
        except Exception as e:
            flash(f"An error occurred with Lookyloo: {e}", "error")
            logging.error(f"Lookyloo error: {e}")
    else:
        flash("Lookyloo instance is not reachable.", "error")

    return redirect(url_for('quishing.quishing'))
