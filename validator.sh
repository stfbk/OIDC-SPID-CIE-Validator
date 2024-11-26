#!/bin/bash

# Create virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi

# Activate virtual environment
source .venv/bin/activate

# Install dependencies and suppress output but not errors
pip install -r requirements.txt > /dev/null

# Run the main script with arguments
python3 tool/mig_validator.py "$@"

# Deactivate virtual environment
deactivate
