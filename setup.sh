#!/bin/bash
echo "Setting up Haunted Terminal CTF Challenge..."

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create necessary directories
mkdir -p journals logs static/sounds

# Create journal files (these will be created by app.py automatically)

echo "Setup complete!"
echo "To run the challenge:"
echo "1. Activate virtual environment: source venv/bin/activate"
echo "2. Run: python app.py"
echo "3. Open browser to: http://localhost:5000"
echo ""
echo "Default users:"
echo "- ghost:admin (but password is hashed)"
echo "- guest:guest"
echo "- spectre:password"
