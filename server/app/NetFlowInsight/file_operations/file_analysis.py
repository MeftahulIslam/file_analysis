import subprocess, os
from flask import flash
import magic
from .result_generation import Scheduler # Importing Scheduler class from result_generation module
import hashlib
from multiprocessing import Queue
import threading




# Function to intiate file analysis
def run_analysis(file_path,pcap_directory, api_key):
    # Setting up queues and threads
    max_threads = os.cpu_count()
    print(f"number of threads: {max_threads}")
    results_input_queue = Queue()
    results_output_queue = Queue()
    NUMBER_OF_THREADS = max_threads #Can be changed according to user needs
    results_workers_threads = [] 

    file_paths = []
    mime_types = []
    file_results = []
    filenames = []
    extension_types = []

    
    # Starting multiple Scheduler instances as worker threads for concurrent processing in the background
    for i in range(NUMBER_OF_THREADS):
        scheduler = Scheduler(input_queue = results_input_queue, output_queue = results_output_queue, api_key = api_key)
        results_workers_threads.append(scheduler)


    # Zeek script path for file extraction
    script_path = "/opt/zeek/share/zeek/policy/frameworks/files/extract-all-files.zeek"
    command = ['zeek', '-C', '-r', file_path, script_path]
    try:
        os.chdir(pcap_directory) # Changing to the pcap directory
        subprocess.run(command, check=True) # Running Zeek to extract/curve files from pcap

        file_analysis_path = os.path.join(pcap_directory,'extract_files') # Path for extracted files

        # Processing extracted files
        if os.path.exists(file_analysis_path):
            for item in os.listdir(file_analysis_path):
                item_path = os.path.join(file_analysis_path,item)
                results_input_queue.put(item_path) # Putting extracted/carved file paths into the input queue for analysis


            for i in range(NUMBER_OF_THREADS):
                results_input_queue.put("DONE") # To signal all threads to stop, one "DONE" for each thread

            
            # Waiting for all worker threads to finish processing
            for i in range(len(results_workers_threads)):
                results_workers_threads[i].join()   
            
            # Retrieving results from the worker threads from output queue
            while True:
                if results_output_queue.empty(): #runs until the output queue is empty
                    break
                #retrieves results from queue one by one and unpacks to variables
                item_path, mime_type, analysis, filename, extension_type = results_output_queue.get()
                print(mime_type) #for debugging

                #putting the results into lists to return
                file_paths.append(item_path)
                mime_types.append(mime_type)
                file_results.append(analysis)
                filenames.append(filename)
                extension_types.append(extension_type)

            flash("Analysis completed successfully.", category='success')

            #returning the lists with results and info about extracted/carved files
            return file_analysis_path, file_paths, mime_types, file_results, filenames, extension_types
        else:
            #If no files were found for extraction return False
            return False, False, False, False, False, False
                
    except subprocess.CalledProcessError as e:
        print(f'{e}') #logging error in console for debugging
