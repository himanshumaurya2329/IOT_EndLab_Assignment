"""
pytest configuration for IoTShield tests.
Adds the project root to sys.path so all modules are importable.
"""
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

