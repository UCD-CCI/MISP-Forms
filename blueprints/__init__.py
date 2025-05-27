from flask import Flask


from blueprints.disinformation import disinformation_bp
from blueprints.dynamoc_form import dynamic_form_bp
from blueprints.index import index_bp
from blueprints.malware import malware_bp
from blueprints.ransomware import ransomware_bp
from blueprints.smishing import smishing_bp
from blueprints.phishing import phishing_bp
from blueprints.defacement import defacement_bp
from blueprints.ddos import ddos_bp
from blueprints.sql_injection import sql_injection_bp
from blueprints.upload_eml import upload_eml_bp
from blueprints.typo_squatting import typo_squatting_bp
from blueprints.scam_website import scam_website_bp
from blueprints.xss import xss_bp
from blueprints.quishing import quishing_bp
from blueprints.feed import feed_bp
from blueprints.disinformation import disinformation_bp
from blueprints.invoice import invoice_bp
from blueprints.mitm import mitm_bp
from blueprints.social_eng import social_eng_bp
from blueprints.vishing import vishing_bp
from blueprints.password_attack import password_attack_bp
from blueprints.news import news_bp

import os

def create_app():
    app = Flask(__name__, static_folder='../static', template_folder='../templates')
    app.secret_key = os.getenv('FLASK_SECRET_KEY')


    # Register blueprints
    app.register_blueprint(index_bp)
    app.register_blueprint(phishing_bp)
    app.register_blueprint(defacement_bp)
    app.register_blueprint(ddos_bp)
    app.register_blueprint(upload_eml_bp)
    app.register_blueprint(typo_squatting_bp)
    app.register_blueprint(scam_website_bp)
    app.register_blueprint(xss_bp)
    app.register_blueprint(ransomware_bp)
    app.register_blueprint(malware_bp)
    app.register_blueprint(sql_injection_bp)
    app.register_blueprint(dynamic_form_bp)
    app.register_blueprint(smishing_bp)
    app.register_blueprint(quishing_bp)
    app.register_blueprint(disinformation_bp)
    app.register_blueprint(invoice_bp)
    app.register_blueprint(mitm_bp)
    app.register_blueprint(social_eng_bp)
    app.register_blueprint(vishing_bp)
    app.register_blueprint(password_attack_bp)
    app.register_blueprint(news_bp)

    return app
