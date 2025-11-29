# Secure implementation of a medical record lookup
from flask import Flask, request, abort
import re

app = Flask(__name__)

def validate_national_id(nid):
    # Saudi National ID format validation (10 digits, starts with 1 or 2)
    if not re.match(r'^[1-2][0-9]{9}$', nid):
        return False
    return True

@app.route('/api/v1/medical_record', methods=['POST'])
def get_record():
    current_user = get_current_user() # Assumes Nafath integration
    target_id = request.json.get('national_id')

    # 1. Input Validation
    if not validate_national_id(target_id):
        return abort(400, "Invalid National ID format")

    # 2. Access Control (Broken Access Control prevention)
    # User can only view their own record or their dependents
    if current_user.id != target_id and target_id not in current_user.dependents:
        # Log this unauthorized attempt!
        log_security_event(current_user.id, "UNAUTHORIZED_ACCESS_ATTEMPT")
        return abort(403, "You do not have permission to view this record")

    # 3. Secure Query (Prevent SQL Injection)
    # Using ORM (Object Relational Mapping) instead of raw SQL
    record = MedicalRecords.query.filter_by(patient_id=target_id).first()

    return record.encrypt_for_transit() # Return encrypted JSON
