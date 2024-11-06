import argparse
from datetime import datetime
from urllib.parse import urlparse
import os

#To print the result
from rich.console import Console
from rich.table import Table
from rich.text import Text

# Markdown output file
OUTPUT_MD_FILE = "output/"
VERBOSE = False

#Creates a folder or file given a path.
def _create_if_not_exist(path: str):
    if not os.path.exists(path):
        os.makedirs(path)

#Get time for the filename
def get_timestamp_filename(extension, hostname):
    timestamp = datetime.now().strftime("%Y_%m_%d_" + hostname) # + "_%H%M%S" for seconds
    return f"{timestamp}.{extension}"

#Function to filter out PASSED tests
def filter_fail (test_results):
    filtered_results = []

    for test in test_results:
        if test["Test Result"] != "PASSED":
            #If a test is not PASSED, add it to the filtered results
            filtered_results.append(test)

    return filtered_results

#Function to determine the style of the ID (bold, italic, normal)
def style_id(id, test_result):
    parts = id.split('.')
    if len(parts) == 1:
        return Text(id, style="bold")
    elif test_result not in ["", "PASSED", "FAILED"]:
        return Text(id, style="italic")
    else:
        return Text(id)

#Function to style the Markdown version of the ID
def style_id_md(id, test_result):
    parts = id.split('.')
    if len(parts) == 1:
        return f"**{id}**"
    elif test_result not in ["", "PASSED", "FAILED"]:
        return f"*{id}*"
    else:
        return id

#Function to style the Markdown result with colors using inline HTML
def style_result_md(result):
    if result in ["[WARNING]", "[MISSING]", "MISSING"]:
        return f"<span style='color: orange;'>**{result}**</span>"
    elif result in ["PASSED", "[PASSED]"]:
        return f"<span style='color: green;'>**{result}**</span>"
    elif result in ["FAILED", "[FAILED]"]:
        return f"<span style='color: red;'>**{result}**</span>"
    else:
        return result

#Function to generate colored terminal output
def print_table_in_terminal(test_results):
    console = Console()
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("ID", style="bold")
    table.add_column("Test Name", overflow="fold")
    table.add_column("Test Result")
    table.add_column("Reason/Mitigations", overflow="fold")

    if not VERBOSE:
        test_results = filter_fail(test_results)

    for test in test_results:
        # Style the Test Result column
        result_text = Text(test["Test Result"])
        if test["Test Result"] in ["[WARNING]", "[MISSING]", "MISSING"]:
            result_text.stylize("bold yellow")
        elif test["Test Result"] in ["PASSED", "[PASSED]"]:
            result_text.stylize("bold green")
        elif test["Test Result"] in ["FAILED", "[FAILED]", "ERROR", "[ERROR]"]:
            result_text.stylize("bold red")
        
        # Style the ID based on the number of parts
        styled_id = style_id(test["ID"], test["Test Result"])

        # Style the Test Name (in italics for sub-tests)
        styled_test_name = Text(test["Test Name"])
        if len(test["ID"].split('.')) == 1:
            styled_test_name.stylize("bold")
        elif test["Test Result"] not in ["", "PASSED", "FAILED"]:
            styled_test_name.stylize("italic")

        #Add a section row
        if len(test["ID"]) == 1:
            table.add_section()
            table.add_row(styled_id, styled_test_name, result_text, test["Reason/Mitigation"])
            table.add_section()
        else:
            table.add_row(styled_id, styled_test_name, result_text, test["Reason/Mitigation"])
    
    console.print(table)

#Function to generate markdown output with colors
def write_table_to_md(test_results, output_file, hostname:str):
    with open(output_file, 'a') as f:
        #Add title on what's the main RP
        f.write("\n# " + hostname + "\n\n")
        # Write table header
        f.write("| ID | Test Name | Test Result | Reason |\n")
        f.write("|---|------------|-------------|--------|\n")

        # Write table rows
        for test in test_results:
            styled_id = style_id_md(test["ID"], test["Test Result"])
            styled_test_name = test["Test Name"]
            
            # Apply italics to the test name for sub-tests in markdown
            if len(test["ID"].split('.')) == 1:
                styled_test_name = f"**{test['Test Name']}**"
            elif test["Test Result"] not in ["", "PASSED", "FAILED"]:
                styled_test_name = f"*{test['Test Name']}*"

            # Apply color to the test result
            styled_result = style_result_md(test["Test Result"])
            
            # In md table \n must be replaced or will disrupt the table
            new_tests = test['Reason/Mitigation'].replace('\n', '<br>')
            f.write(f"| {styled_id} | {styled_test_name} | {styled_result} | {new_tests} |\n")

#Function to sort by ID, treating the ID as a multi-level hierarchy
def sort_by_id(entry) -> list:
    return [int(part) for part in entry['ID'].split('.')]

def main(test_results: list, verbose: bool, url_rp: str):
    global VERBOSE
    if verbose:
        VERBOSE = True
    
    #Check if the folder is present
    _create_if_not_exist(OUTPUT_MD_FILE)

    if url_rp:
        hostname = (urlparse(url_rp).hostname).replace(".","_")
    else:
        url_rp = hostname = "No_URL_RP"
    
    #Sort the table by the provided key
    test_results = sorted(test_results, key = sort_by_id)

    #Print the table in terminal with colors
    print_table_in_terminal(test_results)
    
    filename = OUTPUT_MD_FILE+get_timestamp_filename("md", hostname)

    #Write the table to markdown file with colors
    write_table_to_md(test_results, filename, url_rp)

    print("NOTE. The verification of the algorithms that MUST NOT be present has been performed. Remember that OP MUST/SHOULD support:\n - Signature ['RS256', 'RS512', 'ES256', 'ES512', 'PS256', 'PS512']\n - Key Encryption ['RSA-OAEP', 'RSA-OAEP-256', 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A256KW']\n - Content Encryption ['A128CBC-HS256', 'A128CBC-HS512']\n")
    print(f"Verbose markdown table has been written to {filename}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tool for processing URLs given the URL of the Relying Party (URL_RP) and the Authorization Request")

    #Admitted arguments
    parser.add_argument('--verbose', action='store_true', help='Specify for a verbose output.')

    #Parse the arguments
    args = parser.parse_args()

    #Extract arguments
    if args.verbose:
        VERBOSE = True

    # Print the table in terminal with colors
    print_table_in_terminal(test_results)
    
    # Write the table to markdown file with colors
    write_table_to_md(test_results, OUTPUT_MD_FILE)

    print(f"\nVerbose markdown table has been written to {OUTPUT_MD_FILE}")
