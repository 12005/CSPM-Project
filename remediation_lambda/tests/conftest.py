import sys, os
# Makes remediation_lambda/plugins/ importable (iam, s3, sg, cloudtrail)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "plugins"))
