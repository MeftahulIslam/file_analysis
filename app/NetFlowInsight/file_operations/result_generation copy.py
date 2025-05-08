import openai, subprocess, json, time, os, magic, threading, hashlib
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
            _item_path = self._input_queue.get() #when an a filepath is sent for analysis, threads collects for analysis
            print(f"got one item {_item_path}") #For debugging
            if _item_path == "DONE": # each thread checks for keyword to stop execution 
                break
            result_generation = Result_Generation(_item_path, self._api_key) #initializing object
            mime_type, analysis, filename, extension_type = result_generation.file_result_generation() #running analysis
            results = [_item_path, mime_type, analysis, filename, extension_type] #storing results in a list to send to ouput queue
            print(results) #for debugging
            self._output_queue.put(results) #stores results in the output queue for retrieving later





   

#responsible for file analysis and result generation
class Result_Generation():
    def __init__(self, item_path, api_key):
        self._item_path = item_path
        self._api_key = api_key

    # method for file analysis and result generation
    def file_result_generation(self):
        file_mime_type = magic.Magic(mime=True)
        mime_type = file_mime_type.from_file(self._item_path)

        #hashing file content for filename
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

        #if text of binary file, sends first to hybrid analysis
        parts = mime_type.split('/')
        if parts[0] == 'text' or parts[0] == 'application':
            analysis = self._analyze_file_hybrid_analysis(parts[0])
        else:
            analysis = f"This is a {extension_type} file" #all other file types are not analyzed for the timebeing
        return mime_type, analysis, filename, extension_type
    
    # extracting file extension type from MIME type
    def _get_extension_type(self, mime_type):
        parts = mime_type.split('/')
        return parts[1]
    
    # Analyzing file content using OpenAI for text based file types
    #Can handle less than 4097 for now. 
    def _analyze_file_openai(self):
        # OpenAI analysis based on file content
        openai.api_key = self._api_key
        analysis = "Something went wrong! Unknown error!"
        try:
            with open(self._item_path, 'r') as file:
                file_contents = file.read()

            prompt = f"Analyze the contents of this file:\n{file_contents}\n\nExplain what the code is doing in details and provide a verdict if the contents of the file are malicious."

            response = openai.Completion.create(
                engine = 'text-davinci-003',
                prompt = prompt,
                max_tokens = 200,
                n = 1,
                stop = None,
                temperature = 0.7
            )

            analysis = response.choices[0].text.strip()
            print(f'1 file analyzed by openai')
            return analysis #returns OpenAI analysis


        except Exception as e:
            print(f'{e}') #for debugging
            return analysis



            
    def _analyze_file_hybrid_analysis(self,mime_type):
            openai.api_key = self._api_key
            analysis = "Something went wrong! Unknown error!"
            print("started analyzing...") #for debugging

            # path to the VxAPI script, responsible for Hybrid Analysis python api
            vxapi_path = '/opt/app/VxAPI-master/vxapi.py'
            command = ['python3', vxapi_path, 'scan_file', self._item_path, 'all']
            try:
                result = subprocess.run(command, capture_output=True, text=True, check=True)
                output = result.stdout.strip()
                data = json.loads(output)
                sha256 = data["sha256"]
                time.sleep(5)

                # Execute the scan using Hybrid Analysis api
                command = ['python3', vxapi_path, 'overview_get', sha256]
                result = subprocess.run(command, capture_output=True, text=True, check=True)
                print("got the fileresult...")
                output = result.stdout.strip()
                data = json.loads(output)

                #sending to OpenAI for formatting the json to natural language
                prompt = f"""Give me brief analysis of the report in this format(This part cannot be in the output):\n
                            Scores:\n
                            \nMetadefender:
                            \nVirusTotal:
                            \nCrowdStrike Falcon Static Analysis (ML):
                            \nFinal Verdict:
                            \n\n
                            These are the only text that you can keep in the output
                            This is the report to analyze:
                            {data}"""

                response = openai.Completion.create(
                    engine = 'text-davinci-003',
                    prompt = prompt,
                    max_tokens = 200,
                    n = 1,
                    stop = None,
                    temperature = 0.7
                )

                analysis = response.choices[0].text.strip()  

                #If the text based file is malicious sends to OpenAI for analysis
                if "Final Verdict: Malicious" in analysis:
                    if mime_type == "text":
                        open_ai_analysis = self._analyze_file_openai()
                        analysis = analysis + "\n\nOpenAi Analysis:\n"+ open_ai_analysis
                        print('1 file successfully analyzed by Hybrid Analysis')
                        return analysis   
                return analysis
            
            except openai.error.AuthenticationError as e: #if user provided api key is not valid, the result is stored as a warning
                analysis = """Incorrect OpenAI API key provided! \nCouldn't Analyze! 
                \nPlease change the OpenAI API key from your Profile!"""
                return analysis
            
            except Exception as e: #for debugging all other types of exceptions
                print(f'{e}')
                return analysis