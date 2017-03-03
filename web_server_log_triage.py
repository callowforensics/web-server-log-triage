#!/usr/bin/env python3

import argparse
import os
import sys
import re
import gzip
import time
import urllib
import tarfile
import urllib.parse
import platform
import textwrap
import shutil
import pickle

__author__ = "Andrew Callow"
__copyright__ = "Copyright (C) 2016, HPE ESS"
__title__ = "web_server_log_triage.py"
__license__ = "Proprietary"
__version__ = "1.0"
__email__ = "acallow@btinternet.com"
__status__ = "Prototype"


def check_args():
    """Checks the arguments.

    Corrects any omitted path suffixes, checks if the input/output directory exists. It also sets a global variable
    that defines whether the script uses Windows or Linux related searches of the logs.
    """
    # Check if the input directory exists. If it doesn't, exit the program.
    if not os.path.exists(arguments.input):
        print("\nThe specified input directory does not exist!")
        sys.exit()

    # Check if the output directory exists, if it does exit create it, or ask the user if it can be overwritten.
    if os.path.exists(arguments.output):
        proceed = input("\nThe specified output directory already exists! Enter \"D\", to delete it and continue, "
                        "or \"Q\" to exit the program: ")
        if proceed.lower() == "d":
            shutil.rmtree(arguments.output)
            os.makedirs(arguments.output)
            os.system(CLEAR_SCREEN)
        else:
            sys.exit()
    else:
        os.makedirs(arguments.output)


def open_file(file_to_open=None):
    """Opens a file.

    Opens either .gz, .tar.gz, tar, or just plain text files (detection based on file extension only).

    Args:
        file_to_open: The file to be opened.
    Returns:
        File object.
    """
    # split the filename to make it easy to differentiate between .tar and tar.gz.
    split_file_to_open = file_to_open.split(".")

    # Return a file object
    if file_to_open.endswith(".txt"):
        f = open(file_to_open, 'r', encoding="ISO-8859-1")  # ISO-8859-1 else Unicode errors when searching.
        return f

    elif file_to_open.endswith("log"):
        f = open(file_to_open, 'r', encoding="ISO-8859-1")  # ISO-8859-1 else Unicode errors when searching.
        return f

    elif split_file_to_open[-1] == "gz":
        f = gzip.open(file_to_open, 'r')  # Encoding methods not allowed for .gz.
        return f

    elif split_file_to_open[-2] == "tar" and split_file_to_open[-1] == "gz":
        f = tarfile.open(file_to_open, 'r')  # Encoding methods not allowed for .gz.
        return f

    elif file_to_open.endswith(".tar"):
        f = tarfile.open(file_to_open, 'r')  # Encoding methods not allowed for .tar/.tar.gz.
        return f

    elif file_to_open.endswith(".zip"):
        print("Opening of zip files not currently supported!")
        sys.exit()

    else:
        f = open(file_to_open, 'r', encoding="ISO-8859-1")  # Encoding methods not allowed for .tar/.tar.gz.
        return f


def yield_log_lines(object_to_yield_from=None):
    """Generator to return log lines.

    Yields log lines.

    Args:
        object_to_yield_from: The file from which the log lines should be yielded from.
    Returns:
        log lines.
    """
    # Loop through the log lines and yield them.
    for line in object_to_yield_from:
        if type(line) == bytes:
            yield line.decode("ISO-8859-1")
        else:
            yield line


def get_valid_logs():
    """Searches logs to identify only those that contain valid HTTP access requests

    Searches all logs within the given input directory to find logs that contain valid HTTP access requests. This
    is achieved by searching the logs for valid HTTP commands.
    """

    # Tell the user the search has started.
    output = "Searching for valid logs..."
    print("#" * len(output), "\n")
    print(output, "\n")
    print("#" * len(output), "\n")

    # Create a list to store log lines in
    log_lines = []
    # create a list to store log lines containing more than 1 IP address.
    multiple_ip_logs = []

    # If a log line with 2x IPs is found, the logs are stored within the multiple IP list.
    for path, dirs, files in os.walk(arguments.input):
        for filename in files:
            fullpath = os.path.join(path, filename)
            file_to_open = open_file(file_to_open=fullpath)
            if not file_to_open:
                errors.write("The file: \"{}\" could not be opened as its file format was not determined\n"
                             .format(fullpath))
                continue
            else:
                line_counter = 0
                for log_line in yield_log_lines(file_to_open):
                    line_counter += 1
                    if arguments.type.lower() == "iis" and line_counter < 5:
                        continue
                    if "GET" in log_line or "POST" in log_line or "HEAD" in log_line or "PUT" in log_line:
                        log_lines.append(log_line)
                        file_store.append(fullpath)
                        # Counter used to determine whether more than 1x remote IP is located.
                        if arguments.type.lower() == "apache":
                            ip_counter = 0
                            for data_field in log_line.split():
                                searchobj = re.match(IP_SEARCH, data_field)
                                if searchobj:
                                    ip_counter += 1
                                searchobj1 = re.match("\"True-Client-IP=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", data_field)
                                if searchobj1:
                                    ip_counter += 1

                            if ip_counter >= 2:
                                multiple_ip_logs.append(log_line)
                            break

                        else:
                            break
                    else:
                        break

            file_to_open.close()
            continue

    # Print a summary of the valid logs found.
    print("\n{} valid log file(s) found\n".format(len(file_store)))
    print("#" * len(output), "\n")

    # give the user chance to see the number of valid logs and clear the terminal.
    time.sleep(2)
    os.system(CLEAR_SCREEN)

    # invoke find index positions function.
    find_index_positions(log_lines=log_lines, multiple_ip=multiple_ip_logs)


def find_index_positions(log_lines=None, multiple_ip=None):
    """Finds fields within log entries.

    Automatically finds fields for IIS logs by reading the field definitions at the top of the file.
    Apache logs are not automatically parsed as there are too many variables to make this worth while; this is
    best left to the user. The positions found are needed because they are used by other functions such as
    get_ip_address and decode_uri.

    Args:
        log_lines: List of all logs lines stored during the search for valid logs.
            These lines are used when asking the user to confirm apache field positions.
        multiple_ip: List of all found Apache log lines that have more than one IP address in them
    """
    # Execute confirm index positions if type is apache, execute iis_get_date_uri_ip if logs are IIS.
    if arguments.type == "apache":
        confirm_apache_index_pos(log_lines=log_lines, multiple_ip=multiple_ip)
    else:
        find_iis_index_pos()


def find_iis_index_pos():
    """Finds date, URI and IP fields within IIS log file.

    Finds date, URI and IP fields within IIS log file.
    """
    # Variables used to search for the c-ip, cs-uri-stem and date fields within IIS logs.
    ip_search_iis, uri_search_iis, date_search_iis = "c-ip", "cs-uri-stem", "date"

    # Read the lines and search for the above referenced fields using regex.
    file_to_open = open_file(file_store[0])
    for line in file_to_open:
        if "#Fields" in line:
            line = line.split()
            for i in range(len(line)):
                searchobj_ip = re.search(ip_search_iis, line[i], re.I)
                if searchobj_ip:
                    # Take 1 of the total to account for the $Fields position.
                    ip_pos = i - 1
                    ip_positions.append(ip_pos)

                searchobj_uri = re.search(uri_search_iis, line[i], re.I)
                if searchobj_uri:
                    # Take 1 of the total to account for the $Fields position.
                    arguments.uri_pos = i - 1

                searchobj_date = re.search(date_search_iis, line[i], re.I)
                if searchobj_date:
                    # Take 1 of the total to account for the $Fields position.
                    arguments.date_pos = i

            break

    # Execute search data function.
    search_data()


def confirm_apache_index_pos(log_lines=None, multiple_ip=None):
    """Prompts the user to confirm Apache field positions.

    Each line in the log_lines list is available to be viewed by the user in order to make decisions about the index
    positions.

    Args:
        log_lines: List containing all log lines collected earlier in script.
        multiple_ip: List of all found Apache log lines that have more than one IP address in them
    """

    # Print if multiple IP addresses are found within Apache logs.
    if multiple_ip:
        multiple_ip_string = ("Apache logs with multiple IP addresses have been located."
                              " The presence of multiple IP addresses within Apache logs is usually because the first "
                              "field in the log contains the IP address of a Load Balancer rather than the actual "
                              "remote IP that made the request to the web-server. It is recommended that, where "
                              "present, the \"True-Client-IP\" is selected as the remote IP position. In the absence "
                              "of the \"True-Client-IP field, the presence of multiple IP addresses within Apache logs "
                              "is likely due to XFF.")

        print("ATTENTION:\n")
        print(textwrap.fill(multiple_ip_string, 200))  # Wrap the text (200 chars).
        print(TOP_BANNER)
        print("\nThe following log line (broken into fields) cam be used to set "
              "the positions of the remote IP(s), date and URI:")

    # Print if multiple IP addresses are not found within Apache logs.
    else:
        print("\nThe following log line (broken into fields) should be used to set "
              "the positions of the remote IP(s), date and URI:")

    # Set a variable to control while loop.
    load_logs = True

    # Set the valid list to load into yield_log_lines.
    if multiple_ip:
        database = multiple_ip
    else:
        database = log_lines

    # Set an initial log count.
    log_count = 0

    # Execute until the user does not want to see any more log entries.
    while load_logs:
        for log_line in yield_log_lines(object_to_yield_from=database):
            if log_line:
                log_count += 1
                print(TOP_BANNER)

                for index, field in enumerate(log_line.split()):
                    print("{}: {}".format(index, field))
                print(TOP_BANNER)
                print("The above is log line extract {} of {}.".format(log_count, len(database)))
                choice = input("\nWould you like to view another log line extract (enter \"(y)es\" or \"(n)o\"): ")

                if choice.lower() == "no" or choice.lower() == "n":
                    load_logs = False
                    break

    # Get the remote IP positions, split the ips entered and add them to a list as integers.
    get_ip = input("\n--Please enter the remote IP position(s) delimited by a space: ")
    for ip in get_ip.split():
        ip_positions.append(int(ip))

    # Get the date position and store as integer.
    get_date = input("\n--Please enter the date position: ")
    arguments.date_pos = int(get_date)

    # Get the URI position and store as integer.
    get_uri = input("\n--Please enter the URI position: ")
    arguments.uri_pos = int(get_uri)

    # Clear the terminal.
    os.system(CLEAR_SCREEN)

    # Invoke search_data function.
    search_data()


def search_data():
    """Searches the valid web-logs for commands that may in-fact be nefarious.

    Each log line is searched using patterns designed to identify nefarious activity. The majority of the searches
    are for admin type commands such as "ipconfig", "netstat" etc.
    """
    # Counter to increment the file number being read.
    file_counter = int(1)
    # Set a variable to store the number of hits.
    hits = 0

    # Print some information about the search phase.
    if arguments.mode == "full":
        phase_1 = "SEARCH PHASE ONE: Searching for potentially nefarious commands\n"
        print("#" * len(phase_1), "\n")
        print(phase_1)
    else:
        phase_1 = "Searching for potentially nefarious commands\n"
        print("#" * len(phase_1), "\n")
        print("Searching for potentially nefarious commands\n")

    # Print a new line for correct formatting of the below loop's output.
    print("#" * len(phase_1), "\n")

    for file in sorted(file_store):
        file_to_open = open_file(file_to_open=file)
        line_counter = 0
        print("Searching the file: \"{}\" ({}/{})".format(file, file_counter, len(file_store)), end="\r")
        file_counter += 1

        for log_line in yield_log_lines(object_to_yield_from=file_to_open):
            line_counter += 1
            for command in data_store:
                # Create a variable to store the nested dictionary name.
                search = data_store[command]
                # Process the non-regex searches.
                if search["type"] == "standard":
                    if search["pattern"] in log_line.lower():
                        get_ip_address(line=log_line, line_number=line_counter, file_name=file)
                        get_page(line=log_line, line_number=line_counter, file_name=file)
                        hit = uri_decode(line=log_line, line_number=line_counter, file_name=file)
                        search["hits"].append(hit + "\n\n")
                        hits += 1
                # Process the regex searches.
                else:
                    searchobj = re.search(search["pattern"], log_line.lower(), re.I)
                    if searchobj:
                        get_ip_address(line=log_line, line_number=line_counter, file_name=file)
                        get_page(line=log_line, line_number=line_counter, file_name=file)
                        hit = uri_decode(line=log_line, line_number=line_counter, file_name=file)
                        search["hits"].append(hit + "\n\n")
                        hits += 1

        # Close the file.
        file_to_open.close()

    # Print the cumulative hits.
    print("\n\nCUMULATIVE HITS: {}\n".format(hits))


def get_ip_address(line=None, line_number=None, file_name=None):
    """Searches a log line for the remote IP address.

    The remote IP address is searched for based on the value entered/determined earlier in the script. These IP
    addresses are needed so that the logs can be searches again so that all logs with reference to a notable IP can
    be found.

    Args:
        line: A log line to be used by the function
        line_number: The line that has been passed to the function.
        file_name: The name of the file from which the log is from.
    Returns:
        To search_data().
    Raises:
        IndexError: Error when attempting to collect remote IP.
    """

    try:
        for i in ip_positions:
            ip = line.split()[i]
            searchobj = re.search(IP_SEARCH, ip)
            if searchobj:
                if ip not in ip_store:
                    ip_store.append(ip)
    # Raise exception if any errors are encountered.
    except IndexError:
        errors.write("IndexError: Error attempting to collect IP address from the file: \"{}\" (line {}).\n"
                     .format(file_name, line_number))

    return


def get_page(line=None, line_number=None, file_name=None):
    """Decodes a URI and returns the log line with the decoded URI.

    The URI is determined based on the value entered/determined earlier in the script.

    Args:
        line: A log line to be used by the function.
        line_number: The line that has been passed to the function. Default value is "None" because "get_all_logs()"
            does not send a line number to the function.
        file_name: The name of the file from which the log is from. Default value is "None" because "get_all_logs()"
            does not send a line number to the function.
    Returns:
        To search_data().
    Raises:
        IndexError: Error when attempting to decode URI.
    """
    try:
        uri_to_search = line.split()[arguments.uri_pos]
        search = re.match(".*\.(jsp|asp|aspx|ashx|php|htm|html|cshtml|phtml|shtml|xhtml|"
                          "jhtml|sht|ascx|xtml|nasmx|phps|xht|php4)", uri_to_search, re.I)
        if search:
            hit_extents = search.span()
            start_pos = hit_extents[0]
            end_pos = hit_extents[1]
            page = uri_to_search[start_pos:end_pos]
            if page not in page_store:
                page_store.append(page)
        return

    except IndexError:
        errors.write("IndexError: Error attempting to collect page-name from the file: \"{}\" (line {}).\n"
                     .format(file_name, line_number))
        return


def uri_decode(line, line_number=None, file_name=None):
    """Decodes a URI and returns the log line with the decoded URI.

    The URI is determined based on the value entered/determined earlier in the script.

    Args:
        line: A log line to be used by the function.
        line_number: The line that has been passed to the function. Default value is "None" because "get_all_logs()"
            does not send a line number to the function.
        file_name: The name of the file from which the log is from. Default value is "None" because "get_all_logs()"
            does not send a line number to the function.
    Returns:
        To search_data().
    Raises:
        IndexError: Error when attempting to decode URI.
    """
    try:
        uri_decode_line = line.split()
        uri_decoded = urllib.parse.unquote(uri_decode_line[arguments.uri_pos])
        uri_decode_line[arguments.uri_pos] = uri_decoded  # Assign the decoded field back to the list.
        joined = " ".join(uri_decode_line)
        return joined
    except IndexError:
        errors.write("IndexError: Error attempting to collect IP address from the file: \"{}\" (line {}).\n"
                     .format(file_name, line_number))
        return


def clean_logs():
    """Cleans up any erroneous characters within a collected remote IP address.

    Builds a new IP address string by removing characters that are not numeric or a period.
    """

    # list to store filtered IPs
    filtered_ips = []

    bad_chars = [c for i in ip_store for c in i if not re.search("[0-9.]", c, re.I)]
    bad_chars = set(bad_chars)  # De-dupe the bad_chars

    for i in ip_store:
        ip = ""
        for x in range(len(i)):  # Loop through each char in ip.
            if not any(i[x] == c for c in bad_chars):  # Avoid the unwanted chars.
                ip += i[x]  # Build the new string.
        if ip:  # Store the ip if it is not blank.
            filtered_ips.append(ip)

    # Send the filtered_ips and report_items to render_text function.
    render_text(filtered_ips)


def render_text(ips=None):
    """Renders a summary report and full report.

    Creates a summary report with statistics/categories.

    Args:
        ips: The notable IPs located.
    """

    # Create the summary file within the output directory.
    with open(os.path.join(arguments.output, "analysis_summary.txt"), "w") as summary_file:

        # Write the remote IPs.
        summary_file.write("{}\nThe following remote IP(s) of possible interest were identified:{}"
                           .format(TOP_BANNER, BOTTOM_BANNER))

        # Loop through the ips within the sorted ips list.
        for ip in sorted(ips):
            summary_file.write(ip + "\n")

        # Write the potentially compromised web-page names.
        summary_file.write("{}\nThe following page(s) may be compromised:{}".format(TOP_BANNER, BOTTOM_BANNER))

        # Loop through the ips within the sorted ips list.
        for page in sorted(page_store):
            summary_file.write(page + "\n")

        # Print the detailed summary.
        summary_file.write("{}\nThe following is a summary of the possible commands/executions found by the script:{}"
                           .format(TOP_BANNER, BOTTOM_BANNER))

        # Loop through the sorted COMMANDS lists for each command to create a brief summary
        for i in sorted(data_store):
            search = data_store[i]
            summary_file.write("{}: {}\n".format(i, len(search["hits"])))

        # Loop through sorted COMMANDS lists items to create a detailed summary and write the log lines.
        for i in sorted(data_store):
            if data_store[i]["hits"]:
                summary_file.write("{}\nThe following {} log line(s) with reference to \"{}\" commands were "
                                   "identified:{}"
                                   .format(TOP_BANNER, len(data_store[i]["hits"]), i, BOTTOM_BANNER))
                summary_file.writelines(data_store[i]["hits"])

    # Advise that the script has completed if the full mode has not been selected.
    if not arguments.mode == "full":
        print("#" * 50)
        print("\nScript Completed. The results can now be viewed within the output directory:"
              " ({})".format(arguments.output))
    # Or go to get_all_logs.
    else:
        get_all_logs(ips)


def get_all_logs(ips=None):
    """Creates a full time line of possible nefarious activity.

        Produces an ordered list of all logs that reference a
        previously identified remote IP address.

        Args:
        ips: The notable IPs located.
        """

    # Set an integer for hits.
    hits = 0

    # Determines stdout.
    phase_2 = "\nSEARCH PHASE TWO: Searching for all logs that contain IP addresses identified in phase 1\n"
    print("#" * len(phase_2))
    print(phase_2)

    # Print a new line for correct formatting of the below loop's output.
    print("#" * len(phase_2), "\n")

    # Execute if there are ips in the filtered_ips list.
    if ips:
        with open(os.path.join(arguments.output, "all_relevant_logs.txt"), "w") as all_logs:
            counter = int(1)
            for file in sorted(file_store):
                file_to_open = open_file(file)
                print("Searching the file: \"{}\" ({}/{})".format(file, counter, len(file_store)), end="\r")
                counter += 1

                for log_line in yield_log_lines(file_to_open):
                    if any(ip in log_line for ip in ips):
                        uri = uri_decode(log_line)
                        all_logs.write(uri + "\n")
                        hits += 1

                # Close the file.
                file_to_open.close()

        # Print the cumulative hits.
        print("\n\nCUMULATIVE HITS: {}\n".format(hits))

        # Print if ips == true.
        print("#" * len(phase_2))
        print("\nScript Completed. The results can now be viewed within the output directory:"
              " ({})".format(arguments.output))

    # Or print this.
    else:
        print("#" * len(phase_2))
        print("\nNo amalgamated logs produced (either because no commands were found, or commands were found "
              "within logs that exhibit null True-Client-IP fields)")


# Run the script.
if __name__ == "__main__":
    description = ("""This script recursively searches a user specified folder containing web server logs,
    and finds potentially nefarious commands. The script will locate, and decode, plain text URL encoded
    commands that have been issued to a server; it also attempts to find SQL injection as well as possible
    encoded commands (base64 etc). It is a requirement to enter the log type, as each web-server application has its
    own intricacies.""")

    # use case
    epilog = "example: -i /cases/1234/web_server_logs -o /cases/1234/output -t iis -m full -s search_terms.p"

    # arguments
    parser = argparse.ArgumentParser(description=description, epilog=epilog)
    parser.add_argument("--input", "-i", action="store",
                        help="the directory within which the web-server logs are stored.", required=True)
    parser.add_argument("--output", "-o", action="store",
                        help="output directory", required=True)
    parser.add_argument("--searchterms", "-s", action="store",
                        help="search_terms.p file", required=True)
    parser.add_argument("--type", "-t", action="store", choices=["iis", "apache"],
                        help="enter either \"iis\" or \"apache\"", required=True),
    parser.add_argument("--mode", "-m", action="store", choices=["full", "lite"],
                        help="""Full mode: Collects all logs for IPs identified during the search for commands and
                           pieces them together. Lite mode: Just gives a summary of notable commands found (recommended
                           for searching big logs)""", required=True)

    arguments = parser.parse_args()
    # Argument to store date pos.
    arguments.date_pos = int()
    # Argument to store uri pos.
    arguments.uri_pos = int()

    # Set some variables.
    IP_SEARCH = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"  # Regex used to check for valid IPs.
    TOP_BANNER = "\n" + "." * 50 + "\n"  # Used to format output text.
    BOTTOM_BANNER = "\n\n" + "." * 50 + "\n\n"  # Used to format output text.
    file_store = []  # Store a list of files to be parsed.
    ip_store = []  # Store ip addresses of note.
    page_store = []  # Store a list of potentially compromised web-pages.
    ip_positions = []  # Store a list of ip_positions.

    # Set a global variable used to clear the terminal.
    system = platform.system()
    if system.lower() == "linux":
        CLEAR_SCREEN = "clear"
    else:
        CLEAR_SCREEN = "cls"

    # Open the file to store the hits.
    data = open(arguments.searchterms, "rb")
    data_store = pickle.load(data)
    data.close()

    # Run check_args.
    check_args()

    # Open a file to store errors encountered opening files.
    errors = open(os.path.join(arguments.output, "errors.txt"), "w")

    # Clear the screen.
    os.system(CLEAR_SCREEN)

    # Start the script's timer.
    start = time.time()

    # Find valid logs.
    get_valid_logs()

    # End the program if we don't have hits.
    if not ip_store:
        if arguments.mode == "full":
            print("#" * 50, "\n\nPhase 2 skipped as no potentially nefarious commands found!")
        else:
            print("#" * 50, "\n\nNo potentially nefarious commands found!")
        # Set the end time.
        end_time = int(time.time() - start)

        # Print how long it took.
        if end_time < 60:
            print("\nThe script took " + str(end_time) + " seconds to complete.")
        else:
            time_minutes = end_time / 60
            print("\nThe script took " + str(time_minutes) + " minutes to complete.")

        # Close the errors file.
        errors.close()
        sys.exit()
    else:
        # Run clean logs.
        clean_logs()
        # Set the end time.
        end_time = int(time.time() - start)
        # Print how long it took.
        if end_time < 60:
            print("\nThe script took {} second(s) to complete.".format(end_time))
        else:
            time_minutes = end_time / 60
            print("\nThe script took {} minute(s) to complete.".format(int(time_minutes)))
        # Close the errors file.
        errors.close()
