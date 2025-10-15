#!/usr/bin/env bash
# Helper script to run the test suite in an isolated conda environment
# Activates the 'myenv' conda environment and runs tests
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# Activate the conda environment
source $(conda info --base)/etc/profile.d/conda.sh
conda activate myenv

# Ensure PYTHONPATH includes the project root for sitecustomize.py
export PYTHONPATH="${PYTHONPATH:-}:$(pwd)"

# Install the minimum set of dependencies to run tests and to verify
# ecdsa / jwcrypto integration. This avoids relying on poetry in the CI.
# You can extend this list if your environment needs more packages.
pip install --upgrade pip
pip install "ecdsa==0.19.1" "jwcrypto==0.8" "pytest>=7.2.0" \
    "web3==5.13.1" "eth-utils==1.9.5" "eth-abi==2.1.1" "parsimonious==0.8.1" "mock"

# Run pytest
echo "Running pytest..."
pytest -q

echo "Tests finished with exit code $?"

# Deactivate at the end
conda deactivate
