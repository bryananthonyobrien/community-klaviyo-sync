import sys
import os
from dotenv import load_dotenv

# Add your project directory to the sys.path
project_home = '/home/bryananthonyobrien/mysite'
if project_home not in sys.path:
    sys.path = [project_home] + sys.path

# Load environment variables from a .env file if it exists
dotenv_path = os.path.join(project_home, '.env')
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)

# Ensure single worker process by setting the appropriate environment variable
os.environ["UWSGI_PROCESSES"] = "1"

# Import Flask app but need to call it "application" for WSGI to work
from app import app as application  # noqa
