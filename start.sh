#!/bin/bash
echo "Starting script..."
python --version
echo "Attempting to import main app..."
python -c "from main import app; print('Import successful')"
echo "Starting uvicorn..."
uvicorn main:app --host 0.0.0.0 --port 10000
