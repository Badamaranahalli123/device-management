#!/bin/bash
# Print the Python version to the logs
python --version

# Try to run your app directly with Python to force the error to print
python -c "from main import app; print('Import successful')"

# If the import works, start uvicorn normally
if [ $? -eq 0 ]; then
    echo "Import successful, starting uvicorn..."
    uvicorn main:app --host 0.0.0.0 --port $PORT
else
    echo "Import failed! Check the error above."
    exit 1
fi
