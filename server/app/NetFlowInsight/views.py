from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, send_from_directory
from flask_login import login_required, current_user
from sqlalchemy.orm import joinedload
from werkzeug.utils import secure_filename
from .models import User, Notes, PcapLoc, FileAnalysis, FileResult
from . import db
import os, json, time
from .file_operations.file_analysis import run_analysis
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
from flask_wtf.csrf import validate_csrf
from bleach import clean  # Import bleach for sanitization

# Creating a Blueprint named 'views'
views = Blueprint('views', __name__)

# Flask-Limiter for rate limiting
limiter = Limiter(get_remote_address, app=None)

# Allowed file extensions for uploads
ALLOWED_EXTENSIONS = {'pcap'}

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Route for the home page
@views.route('/')
@login_required
def home():
    return render_template("home.html", user=current_user)

# Route for file upload
@views.route('/upload', methods=['POST'])
@login_required
@limiter.limit("10 per minute")  # Rate limiting to prevent abuse
def upload():
    start_time = time.time()

    file = request.files['pcap_file']

    # Validate file type
    if not file or not allowed_file(file.filename):
        flash('Please include a valid .pcap file', category='error')
        return redirect(url_for('views.home'))

    # Store the file in the user's directory
    user_directory = current_user.path
    api_key = current_user.api_key
    filename = secure_filename(file.filename)

    pcap_directory = os.path.join(str(user_directory), filename)
    if not os.path.exists(pcap_directory):
        os.makedirs(pcap_directory)
    file_path = os.path.join(str(pcap_directory), filename)

    try:
        # Save the file and store details in the database
        file.save(file_path)
        new_file = PcapLoc(path=file_path, filename=filename, user_id=current_user.id)
        db.session.add(new_file)
        db.session.commit()

        pcap_loc_id = new_file.id

        # File Analysis
        file_analysis_path, file_paths, mime_types, file_results, filenames, extension_types = run_analysis(
            file_path, str(pcap_directory), api_key
        )
        if not file_analysis_path:
            file_analysis = FileAnalysis(path="No Files Detected in the Pcap File!", pcap_loc_id=pcap_loc_id)
            db.session.add(file_analysis)
            db.session.commit()
        else:
            file_analysis = FileAnalysis(path=str(file_analysis_path), pcap_loc_id=pcap_loc_id)
            db.session.add(file_analysis)
            db.session.commit()
            file_analysis_id = file_analysis.id
            for file_path,mime_type,file_result,file_name,extension_type in zip(file_paths, mime_types, file_results, filenames, extension_types):
                file_result_new = FileResult(filepath = str(file_path), mime_type=mime_type, result=file_result, filename=file_name, extension_type=extension_type, file_analysis_id = file_analysis_id)
                db.session.add(file_result_new)
            db.session.commit()

        flash(f'File uploaded successfully!', category='success')

        # Log the upload
        logging.info(f"File uploaded by user {current_user.id}: {file_path}")

        # Calculate and log analysis time
        analysis_time = round(time.time() - start_time, 1)
        logging.info(f"File analysis completed in {analysis_time} seconds")
    except Exception as e:
        flash(f'{e}', category='error')
        logging.error(f"Error during file upload: {e}")

    return redirect(url_for('views.home', user=current_user))

# Route for file analysis results
@views.route('file_analysis_results/', methods=['GET', 'POST'])
@login_required
def file_analysis_results():
    if request.method == 'POST':
        try:
            csrf_token = request.headers.get('X-CSRFToken')
            validate_csrf(csrf_token)
        except Exception as e: 
            return jsonify({"error": "Invalid CSRF token"}), 400

    user = User.query.options(
        joinedload(User.pcap_loc)
        .joinedload(PcapLoc.file_analysis)
        .joinedload(FileAnalysis.file_result),
        joinedload(User.pcap_loc)
    ).filter_by(id=current_user.id).first()

    return render_template("file_analysis_results.html", user=user)

# Route for downloading carved files
@views.route('/download/<path:file_path>')
@login_required
def download_file(file_path):
    user_directory = os.path.abspath(current_user.path)  # Get absolute path of the user's directory

    # Normalize and validate the file path
    file_path = os.path.normpath(file_path)
    real_path = os.path.realpath(file_path)

    # Debugging: Log the paths for troubleshooting
    logging.info(f"User Directory: {user_directory}")
    logging.info(f"Requested File Path: {file_path}")
    logging.info(f"Resolved Real Path: {real_path}")

    # Check if the file path is valid and within the user's directory
    if not real_path.startswith(user_directory) or not os.path.exists(real_path):
        flash('Access denied: Invalid file path or file does not exist.', category='error')
        logging.warning(f"Unauthorized file download attempt by user {current_user.id}: {file_path}")
        return redirect(url_for('views.home'))

    # Extract the directory and filename
    directory = os.path.dirname(real_path)
    filename = os.path.basename(real_path)

    # Sanitize the filename
    from werkzeug.utils import secure_filename
    filename = secure_filename(filename)

    # Serve the file for download
    return send_from_directory(directory=directory, path=filename, as_attachment=True)

# Route for updating the API key
@views.route('/update_api_key', methods=['POST'])
@login_required
@limiter.limit("5 per minute")
def update_api_key():
    try:
        # Validate CSRF token
        csrf_token = request.headers.get('X-CSRFToken')
        validate_csrf(csrf_token)

        # Get the new API key from the request
        new_api_key = request.json.get('api_key')
        if not new_api_key:
            return jsonify({"error": "API key cannot be empty"}), 400

        # Update the user's API key
        user = User.query.get(current_user.id)
        if user:
            user.api_key = new_api_key
            db.session.commit()
            return jsonify({"success": True})
        else:
            return jsonify({"error": "User not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 400
# Route for updating notes
@views.route('/update_notes', methods=['POST'])
@login_required
def update_notes():
    try:
        # Validate CSRF token
        csrf_token = request.headers.get('X-CSRFToken')
        validate_csrf(csrf_token)

        new_note = clean(request.json.get('note'))  # Sanitize input
        note_id = int(request.json.get('note_id'))
        note = Notes.query.get(note_id)

        if not note:
            raise ValueError('Note not found!')

        # Validate ownership through PcapLoc
        pcap_loc = PcapLoc.query.get(note.pcap_loc_id)
        if not pcap_loc or pcap_loc.user_id != current_user.id:
            raise ValueError('Unauthorized access to note!')

        # Update the note
        note.note = new_note
        db.session.commit()
        logging.info(f"Note {note_id} updated by user {current_user.id}")
    except Exception as e:
        flash(f'{e}', category='error')
        logging.error(f"Error updating note {note_id} for user {current_user.id}: {e}")
        return jsonify({"error": "Invalid CSRF token"}), 400

    return jsonify({"success": True})

# Updated delete_note route
@views.route('delete_note/', methods=['POST'])
@login_required
@limiter.limit("5 per minute")
def delete_note():
    try:
        # Validate CSRF token
        csrf_token = request.headers.get('X-CSRFToken')
        validate_csrf(csrf_token)

        note = json.loads(request.data)
        note_id = int(note.get('note_id'))
        note = Notes.query.get(note_id)

        if not note:
            logging.warning(f"Note {note_id} not found for user {current_user.id}")
            return jsonify({"error": "Note not found"}), 404

        # Validate ownership through PcapLoc
        pcap_loc = PcapLoc.query.get(note.pcap_loc_id)
        if not pcap_loc or pcap_loc.user_id != current_user.id:
            logging.warning(f"Unauthorized delete attempt by user {current_user.id} for note {note_id}")
            return jsonify({"error": "Unauthorized or note not found"}), 403

        # Delete the note
        db.session.delete(note)
        db.session.commit()
        logging.info(f"Note {note_id} deleted by user {current_user.id}")
        return jsonify({"success": True})
    except (ValueError, KeyError) as e:
        logging.error(f"Invalid input for delete_note by user {current_user.id}: {e}")
        return jsonify({"error": "Invalid input"}), 400
    

# Route for viewing and creating notes
@views.route('view_notes/', methods=['GET', 'POST'])
@login_required
def view_notes():
    if request.method == 'POST':
        try:
            # Validate CSRF token
            csrf_token = request.form.get('csrf_token')
            validate_csrf(csrf_token)

            note = clean(request.form.get('note'))  # Sanitize input
            file_id = request.form.get('file_id')

            # Validate file ownership
            file = PcapLoc.query.get(file_id)
            if not file or file.user_id != current_user.id:
                flash('Unauthorized access to file!', category='error')
                logging.warning(f"Unauthorized access attempt to file {file_id} by user {current_user.id}")
                return redirect(url_for('views.home'))

            # Validate note content
            if len(note) < 1:
                flash('Empty Note!', category='warning')
            else:
                # Add the new note to the database
                new_note = Notes(note=note, pcap_loc_id=file_id)
                db.session.add(new_note)
                db.session.commit()
                flash('New note added successfully!', category='success')
                logging.info(f"Note added by user {current_user.id} for file {file_id}")
        except Exception as e:
            flash(f'Error: {e}', category='error')
            logging.error(f"Error adding note for user {current_user.id}: {e}")
            return redirect(url_for('views.home'))

    return render_template("view_notes.html", user=current_user)

# Route for the user profile page
@views.route('profile/', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        try:
            csrf_token = request.headers.get('X-CSRFToken')
            validate_csrf(csrf_token)
        except Exception as e: 
            return jsonify({"error": "Invalid CSRF token"}), 400

    # Render the profile page for GET requests or after successful POST
    return render_template("profile.html", user=current_user)