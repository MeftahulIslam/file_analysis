// Helper function to sanitize user input
function sanitizeInput(input) {
  const tempDiv = document.createElement('div');
  tempDiv.textContent = input;
  return tempDiv.innerHTML;
}

// For login and signup page password fields
function toggle_password_visibility(input_id) {
  var input = document.getElementById(input_id);
  var toggleCheckbox = document.getElementById(input_id + "-toggle");
  if (input.type === "password") {
    input.type = "text";
    toggleCheckbox.checked = true;
  } else {
    input.type = "password";
    toggleCheckbox.checked = false;
  }
}


// Send an AJAX request to the Flask backend, handled by delete_note()
function deleteNote(note_id) {
  fetch('/delete_note', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': csrfToken, // Include CSRF token in the headers
    },
    body: JSON.stringify({ note_id: note_id }),
  }).then((_res) => {
    window.location.href = "/view_notes";
  });
}

function editNote(noteID) {
  const listItem = document.querySelector(`[data-note-id='${noteID}']`);
  const noteDisplay = listItem.querySelector('.note-display');
  const noteEditField = listItem.querySelector('.note-edit-field');
  const editNoteInput = listItem.querySelector('.edit-note-input');

  // Sanitize and display the current note value in the edit field
  editNoteInput.value = sanitizeInput(noteDisplay.textContent);

  noteDisplay.style.display = 'none';
  noteEditField.style.display = 'block';
}

function saveEditedNote(noteID) {
  const listItem = document.querySelector(`[data-note-id='${noteID}']`);
  const noteDisplay = listItem.querySelector('.note-display');
  const noteEditField = listItem.querySelector('.note-edit-field');
  const editNoteInput = listItem.querySelector('.edit-note-input');

  // Sanitize and update the displayed note with the edited value
  noteDisplay.textContent = sanitizeInput(editNoteInput.value);

  noteDisplay.style.display = 'inline';
  noteEditField.style.display = 'none';

  const url = '/update_notes';
  const editedNote = editNoteInput.value;

  fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': csrfToken,
    },
    body: JSON.stringify({ note: editedNote, note_id: noteID }),
  })
    .then(response => response.json())
    .then(data => {
      console.log('Response from Flask:', data);
    })
    .catch(error => {
      console.error('Error:', error);
    });
}

function editApiKey() {
  const apiKeyDisplay = document.getElementById('apiKeyDisplay');
  const apiKeyEditField = document.getElementById('apiKeyEditField');
  const editApiKeyInput = document.getElementById('editApiKeyInput');

  // Debugging: Check if elements are found
  if (!apiKeyDisplay || !apiKeyEditField || !editApiKeyInput) {
    console.error("One or more elements not found in the DOM.");
    return;
  }

  // Extract the current API key value (remove masking if present)
  const maskedApiKey = apiKeyDisplay.textContent.trim();
  editApiKeyInput.value = maskedApiKey.replace("****", ""); // Remove "****" for editing

  // Show the edit field and hide the display span
  apiKeyDisplay.style.display = 'none';
  apiKeyEditField.style.display = 'block';
}

// Function to save the edited API key
function saveEditedApiKey() {
  const apiKeyDisplay = document.getElementById('apiKeyDisplay');
  const apiKeyEditField = document.getElementById('apiKeyEditField');
  const editApiKeyInput = document.getElementById('editApiKeyInput');
  const csrfToken = document.querySelector('input[name="csrf_token"]').value; // Get CSRF token from the form

  // Debugging: Check if elements are found
  if (!apiKeyDisplay || !apiKeyEditField || !editApiKeyInput) {
    console.error("One or more elements not found in the DOM.");
    return;
  }

  const editedApiKey = editApiKeyInput.value.trim();
  const url = '/update_api_key';

  // Validate the input
  if (!editedApiKey) {
    alert("API key cannot be empty.");
    return;
  }

  // Send the updated API key with the CSRF token
  fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': csrfToken, // Include the CSRF token in the headers
    },
    body: JSON.stringify({ api_key: editedApiKey }),
  })
    .then(response => response.json())
    .then(data => {
      if (data.success) {
        // Update the display with the new API key (masked)
        apiKeyDisplay.textContent = editedApiKey.slice(0, 4) + "****";
        apiKeyDisplay.style.display = 'inline';
        apiKeyEditField.style.display = 'none';
      } else {
        console.error('Error updating API key:', data.error);
        alert('Failed to update API key. Please try again.');
      }
    })
    .catch(error => {
      console.error('Error:', error);
      alert('An error occurred while updating the API key.');
    });
}
function cancelEditApiKey() {
  const apiKeyDisplay = document.getElementById('apiKeyDisplay');
  const apiKeyEditField = document.getElementById('apiKeyEditField');

  // Debugging: Check if elements are found
  if (!apiKeyDisplay || !apiKeyEditField) {
    console.error("One or more elements not found in the DOM.");
    return;
  }

  // Hide the edit field and show the display span
  apiKeyEditField.style.display = 'none';
  apiKeyDisplay.style.display = 'inline';
}

// Get the CSRF token from the meta tag
const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

// Wrapper function for fetch to include CSRF token
function csrfFetch(url, options = {}) {
    options.headers = {
        ...options.headers,
        'X-CSRFToken': csrfToken, // Add the CSRF token to the headers
    };
    return fetch(url, options);
}


csrfFetch('/file_analysis_results/', {
    method: 'POST',
    body: JSON.stringify({}),
})
    .then(response => response.json())
    .then(data => {
        console.log('Response:', data);
    })
    .catch(error => {
        console.error('Error:', error);
    });