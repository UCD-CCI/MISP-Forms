from dotenv import load_dotenv
from blueprints import create_app

load_dotenv()
app = create_app()

# Development
if __name__ == '__main__':
    app.run(debug=True)

 # Production
 # gunicorn -w 4 -b 127.0.0.1:5000 app:app


