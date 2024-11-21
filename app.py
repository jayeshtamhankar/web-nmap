from flask import Flask, render_template, request
import subprocess
import re

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form.get('target')
    flags = ['-O', '-sV']  # Enable OS detection and service version scan

    # Build the nmap command
    command = ['nmap'] + flags + [target]
    
    try:
        # Execute nmap and capture the output
        result = subprocess.check_output(command, text=True)

        # Extract machine information
        machine_info = extract_machine_info(result)

        # Extract open port and version information
        ports_info = extract_ports_info(result)

    except subprocess.CalledProcessError as e:
        result = f"Error executing nmap: {e}"
        machine_info, ports_info = result, result

    return render_template('index.html', machine_info=machine_info, ports_info=ports_info)

def extract_machine_info(nmap_output):
    """
    Extracts machine information (e.g., OS details) from nmap output.
    """
    machine_info = ""
    match = re.search(r"OS details:\s*(.+)", nmap_output)
    if match:
        machine_info = match.group(1)
    else:
        machine_info = "Machine information not available."
    return machine_info

def extract_ports_info(nmap_output):
    """
    Extracts open ports and their versions from nmap output.
    """
    ports_info = []
    in_ports_section = False
    for line in nmap_output.splitlines():
        if re.match(r"PORT\s+STATE\s+SERVICE\s+VERSION", line):
            in_ports_section = True
            continue
        if in_ports_section:
            if line.strip() == "":  # End of ports section
                break
            ports_info.append(line.strip())
    return "\n".join(ports_info) if ports_info else "No open ports detected."

if __name__ == '__main__':
    app.run(debug=True)
