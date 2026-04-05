import sys
import os

# Add the rule_engine folder (parent of tests/) to the Python path
# so that imports like `from rules_iam import evaluate_iam` work correctly.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
