import subprocess, json, time, os, magic, threading, hashlib
from groq import Groq  # Replace OpenAI import with Groq
from multiprocessing import Queue

# Scheduler class managing thread execution
class Scheduler(threading.Thread):
    def __init__(self, input_queue, output_queue, api_key, **kwargs):
        super(Scheduler, self).__init__(**kwargs)
        self._api_key = api_key
        self._input_queue = input_queue
        self._output_queue = output_queue
        print("starting a thread...")
        self.start()

    # execution method for each thread, runs in the background waiting for input queue
    def run(self):
        while True:
            _item_path = self._input_queue.get()  # when a filepath is sent for analysis, threads collect for analysis
            print(f"got one item {_item_path}")  # For debugging
            if _item_path == "DONE":  # each thread checks for keyword to stop execution
                break
            result_generation = Result_Generation(_item_path, self._api_key)  # initializing object
            mime_type, analysis, filename, extension_type = result_generation.file_result_generation()  # running analysis
            results = [_item_path, mime_type, analysis, filename, extension_type]  # storing results in a list to send to output queue
            print(results)  # for debugging
            self._output_queue.put(results)  # stores results in the output queue for retrieving later

# Responsible for file analysis and result generation
class Result_Generation:
    def __init__(self, item_path, api_key):
        self._item_path = os.path.abspath(item_path)  # Sanitize the file path
        self._api_key = api_key
        self._client = Groq(api_key=api_key)  # Initialize Groq client

    # Method for file analysis and result generation
    def file_result_generation(self):
        file_mime_type = magic.Magic(mime=True)
        mime_type = file_mime_type.from_file(self._item_path)

        # Hashing file content for filename
        with open(self._item_path, 'rb') as file:
            chunk_size = 4096
            hasher = hashlib.sha256()
            while True:
                chunk = file.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
        filename = str(hasher.hexdigest())

        extension_type = self._get_extension_type(mime_type)

        # If text or binary file, sends first to hybrid analysis
        parts = mime_type.split('/')
        if parts[0] == 'text' or parts[0] == 'application':
            analysis = self._analyze_file_hybrid_analysis(parts[0])
        else:
            analysis = f"This is a {extension_type} file"  # All other file types are not analyzed for the time being
        return mime_type, analysis, filename, extension_type

    # Extracting file extension type from MIME type
    def _get_extension_type(self, mime_type):
        parts = mime_type.split('/')
        return parts[1]

    # Analyzing file content using Groq for text-based file types
    def _analyze_file_groq(self):
        analysis = "Something went wrong! Unknown error!"
        try:
            with open(self._item_path, 'r') as file:
                file_contents = file.read()

            prompt = f"Analyze the contents of this file:\n{file_contents}\n\nExplain what language the  the code is in and what it's doing in short (in 150 words or less) and provide a verdict if the contents of the file are malicious."

            response = self._client.chat.completions.create(
                model="llama3-8b-8192",  # Groq model
                messages=[
                    {"role": "user", "content": prompt}
                ],
                max_tokens=200,
                temperature=0.7
            )

            analysis = response.choices[0].message.content.strip()
            print(f'1 file analyzed by Groq')
            return analysis

        except Exception as e:
            print(f'{e}')  # For debugging
            return analysis

    def _analyze_file_hybrid_analysis(self, mime_type):
        analysis = "Something went wrong! Unknown error!"
        print("started analyzing...")  # For debugging

        # Path to the VxAPI script, responsible for Hybrid Analysis Python API
        vxapi_path = '/opt/app/VxAPI-master/vxapi.py'

        # Validate paths
        if not os.path.isfile(self._item_path):
            print(f"Invalid file path: {self._item_path}")
            return "Invalid file path provided for analysis."
        if not os.path.isfile(vxapi_path) or not os.access(vxapi_path, os.X_OK):
            print(f"Invalid script path: {vxapi_path}")
            return "Invalid script path provided for analysis."

        # Command for scanning the file
        command = ['/myenv/bin/python', vxapi_path, 'scan_file', self._item_path, 'all']
        try:
            # Execute the command securely
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            output = result.stdout.strip()
            data = json.loads(output)
            sha256 = data["sha256"]
            time.sleep(7)  # Wait for the scan to complete

            # Command for retrieving the scan overview
            command = ['/myenv/bin/python', vxapi_path, 'overview_get', sha256]
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            print("got the fileresult...")
            output = result.stdout.strip()
            data = json.loads(output)

            # Sending to Groq for formatting the JSON to natural language
            prompt = f"""Give me brief analysis of the report in this format:(This part cannot be in the output)\n
                        Scores:\n
                        \nMetadefender:
                        \nVirusTotal:
                        \nCrowdStrike Falcon Static Analysis (ML):
                        \nFinal Verdict:
                        Above are the only text that you can keep in the output. No extra text should be in the output.
                        This is the report to analyze:
                        {data}"""

            # Using Groq instead of OpenAI
            response = self._client.chat.completions.create(
                model="llama3-8b-8192",  # Groq model
                messages=[
                    {"role": "user", "content": prompt}
                ],
                max_tokens=200,
                temperature=0.7
            )

            analysis = response.choices[0].message.content.strip().lower()


            # If the text-based file is malicious, send to Groq for analysis
            if "final verdict: malicious" in analysis:
                if mime_type == "text":
                    groq_analysis = self._analyze_file_groq()
                    analysis = analysis + "\n\nGroq Analysis:\n" + groq_analysis
                    print('1 file successfully analyzed by Hybrid Analysis')
                    return analysis
            return analysis

        except subprocess.CalledProcessError as e:
            print(f"Subprocess error: {e.stderr}")  # Log the error for debugging
            return "Error occurred during file analysis."
        except json.JSONDecodeError as e:
            print(f"JSON decoding error: {e}")  # Log the error for debugging
            return "Error decoding the analysis result."
        except Exception as e:
            if hasattr(e, 'status_code') and e.status_code == 401:  # Authentication error check for Groq
                analysis = """Incorrect Groq API key provided! \nCouldn't Analyze! 
                \nPlease change the Groq API key from your Profile!"""
                return analysis

            print(f"Unexpected error: {e}")  # For debugging all other types of exceptions
            return analysis