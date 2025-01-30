# backend/app/__init__.py  

from flask import Flask  

app = Flask(__name__)  

@app.route('/')  
def home():  
    return "Hello, World!"  

if __name__ == "__main__":  
    app.run(debug=True)

# Import routes after creating the app to avoid circular imports
from . import routes