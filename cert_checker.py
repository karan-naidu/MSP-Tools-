#!/usr/bin/env python
import subprocess
import datetime
import os
import base64
import json
import re

files = [
    "/home/certs/MspControllerService/MspControllerService.crt",
    "/etc/docker-plugin-certs/cert",
    "/var/nutanix/etc/kubernetes/ssl/apiserver.pem",
    "/var/nutanix/etc/kubernetes/ssl/worker.pem",
    "/var/nutanix/etc/kubernetes/ssl/etcd-client.pem",
    "/var/nutanix/etc/etcd/ssl/server.pem",
    "/etc/etcd/ssl/server.pem",
    "/certs/registry.crt"
]


file_name = 'certificates_entity'
idf_dump_file = 'DUMP-certificates_entity'

idfcli_path = './idfcli'

def generate_certificate_status_system(output_format):
    global files
    print("\n")
    print(f"Certs on File System ")
    if output_format == "console":
        print("%-60s | %-26s | %-26s | %-20s | %-60s | %-40s " % ("File", "Not Before", "Not After", "Certificate Status", "Subject", "Issuer" ))
        print("%-60s | %-26s | %-26s | %-20s | %-60s | %-40s " % ("------------------------------", "--------------------------", "--------------------------", "--------------------", "-------------------------------------------", "----------------------------------------"))

        for file in files:
            if os.path.isfile(file):
                try:
                    openssl_output = subprocess.check_output(["sudo", "openssl", "x509", "-noout", "-dates", "-subject", "-issuer", "-nameopt", "RFC2253", "-in", file]).decode("utf-8")
                    not_before = openssl_output.split("notBefore=")[1].split("\n")[0]
                    not_after = openssl_output.split("notAfter=")[1].split("\n")[0]

                    subject_parts = openssl_output.splitlines()
                    for line in subject_parts:
                        if line.startswith("subject="):
                            subject = line.split("subject=")[1].strip()
                            subject_cn = None
                            subject_o = None
                            subject_ou = None
                            parts = subject.replace("CN=", "CN=").replace(",", ", ").split(", ")
                            for part in parts:
                                if part.startswith("CN="):
                                    subject_cn = part.split("=")[1]
                                elif part.startswith("O="):
                                    subject_o = part.split("=")[1]
                                elif part.startswith("OU="):
                                    subject_ou = part.split("=")[1]
                            break
                    else:
                        subject_cn = "Unknown"
                        subject_o = "Unknown"
                        subject_ou = "Unknown"

                    issuer_parts = openssl_output.splitlines()
                    for line in issuer_parts:
                        if line.startswith("issuer="):
                            issuer = line.split("issuer=")[1].strip()
                            issuer_o = None
                            issuer_cn = None
                            parts = issuer.replace("SN=", "").replace(",", ", ").split(", ")
                            for part in parts:
                                if part.startswith("O="):
                                    issuer_o = part.split("=")[1]
                                elif part.startswith("CN="):
                                    issuer_cn = part.split("=")[1]
                            break
                    else:
                        issuer_o = "Unknown"
                        issuer_cn = "Unknown"

                    not_before_date = datetime.datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                    not_after_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    current_date = datetime.datetime.now()

                    if current_date < not_before_date:
                        status = "Not yet valid"
                    elif current_date > not_after_date:
                        status = "Expired"
                    else:
                        status = "Valid"

                    subject_str = f"O={subject_o}, CN={subject_cn}"
                    if subject_ou:
                        subject_str += f", OU={subject_ou}"
                    issuer_str = f"O={issuer_o}, CN={issuer_cn}"

                    print("%-60s | %-26s | %-26s | %-20s | %-60s | %-40s " % (file, not_before, not_after, status, subject_str, issuer_str))
                    print()
                except subprocess.CalledProcessError as e:
                    print(f"Error processing certificate {file}")
                    print()
            else:
                print("%-60s | %-26s | %-26s | %-20s | %-60s | %-40s " % (file, "N/A", "N/A", "Does not exist", "N/A", "N/A"))
                print()
    elif output_format == "html":
        html_output = """
<html>
  <head>
    <title>Certificate Status</title>
    <style>
      table {
        border-collapse: collapse;
      }
      th, td {
        border: 1px solid #ddd;
        padding: 8px;
        text-align: left;
      }
    </style>
  </head>
  <body>
    <h1>Certificate Status</h1>
    <table>
      <tr>
       <th>File</th>
        <th>Not Before</th>
        <th>Not After</th>
        <th>Certificate Status</th>
        <th>Subject</th>
        <th>Issuer</th>
      </tr>
      <tr>
        <td colspan="6"><hr /></td>
      </tr>
"""

        for file in files:
            if os.path.isfile(file):
                try:
                    openssl_output = subprocess.check_output(["sudo", "openssl", "x509", "-noout", "-dates", "-subject", "-issuer", "-nameopt", "RFC2253", "-in", file]).decode("utf-8")
                    not_before = openssl_output.split("notBefore=")[1].split("\n")[0]
                    not_after = openssl_output.split("notAfter=")[1].split("\n")[0]

                    subject_parts = openssl_output.splitlines()
                    for line in subject_parts:
                        if line.startswith("subject="):
                            subject = line.split("subject=")[1].strip()
                            subject_cn = None
                            subject_o = None
                            subject_ou = None
                            parts = subject.replace("CN=", "CN=").replace(",", ", ").split(", ")
                            for part in parts:
                                if part.startswith("CN="):
                                    subject_cn = part.split("=")[1]
                                elif part.startswith("O="):
                                    subject_o = part.split("=")[1]
                                elif part.startswith("OU="):
                                    subject_ou = part.split("=")[1]
                            break
                    else:
                        subject_cn = "Unknown"
                        subject_o = "Unknown"
                        subject_ou = "Unknown"

                    issuer_parts = openssl_output.splitlines()
                    for line in issuer_parts:
                        if line.startswith("issuer="):
                            issuer = line.split("issuer=")[1].strip()
                            issuer_o = None
                            issuer_cn = None
                            parts = issuer.replace("SN=", "").replace(",", ", ").split(", ")
                            for part in parts:
                                if part.startswith("O="):
                                    issuer_o = part.split("=")[1]
                                elif part.startswith("CN="):
                                    issuer_cn = part.split("=")[1]
                            break
                    else:
                        issuer_o = "Unknown"
                        issuer_cn = "Unknown"

                    not_before_date = datetime.datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                    not_after_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    current_date = datetime.datetime.now()

                    if current_date < not_before_date:
                        status = "Not yet valid"
                    elif current_date > not_after_date:
                        status = "Expired"
                    else:
                        status = "Valid"

                    subject_str = f"O={subject_o}, CN={subject_cn}"
                    if subject_ou:
                        subject_str += f", OU={subject_ou}"
                    issuer_str = f"O={issuer_o}, CN={issuer_cn}"

                    html_output += """
      <tr>
        <td>{}</td>
        <td>{}</td>
        <td>{}</td>
        <td>{}</td>
        <td>{}</td>
        <td>{}</td>
      </tr>
""".format(file, not_before, not_after, status, subject_str, issuer_str)
                except subprocess.CalledProcessError as e:
                    html_output += """
      <tr>
        <td>{}</td>
        <td>N/A</td>
        <td>N/A</td>
        <td>Error processing certificate</td>
        <td>N/A</td>
        <td>N/A</td>
      </tr>
""".format(file)
            else:
                html_output += """
      <tr>
        <td>{}</td>
        <td>N/A</td>
        <td>N/A</td>
        <td>Does not exist</td>
        <td>N/A</td>
        <td>N/A</td>
      </tr>
""".format(file)

        html_output += """
    </table>
  </body>
</html>
"""

        html_pages_dir = "html_pages"
        if not os.path.exists(html_pages_dir):
            os.makedirs(html_pages_dir)
        filename = "certificate_status_system.html"
        filepath = os.path.join(html_pages_dir, filename)
        print("\n")
        print(f"The HTML location for File System Cert Check (MSP): {filepath}")
        with open(filepath, "w") as f:
            f.write(html_output)












def generate_certificate_status_idf(output_format):


    print("\n")

    if os.path.exists(idfcli_path) and os.access(idfcli_path, os.X_OK):
 
            print(f"IDF Data from {file_name}")
            cmd = f"{idfcli_path} get entitytype -o json -e={file_name}  > DUMP-{file_name}"
            os.system(cmd)

    else:
     print("idfcli executable not found in current directory")
     exit(1)

    if not os.path.exists(idf_dump_file):
        print(f"Error: File '{idf_dump_file}' does not exist.")
        exit(1)
    try:
        with open(idf_dump_file, 'r') as f:
            file_content = f.read()
            if file_content:  # Check if the file is not empty
                data = json.loads(file_content)
            else:
                print("Error: The file is empty.")
                return
    except FileNotFoundError:
        print("Error: The file does not exist.")
        return
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON - {e}")
        return
    if not data:
        print(f"Error in reading / extracting {file_name} from IDF")
        exit(1)

    try:
        attribute_data_map = data['entity'][0]['attribute_data_map']
    except KeyError as e:
        print("Error parsing JSON:", e)
        return

    certificates = []
    for entity in data['entity']:
        try:
            attribute_data_map = entity['attribute_data_map']
            certificate_data = next(filter(lambda x: x['name'] == 'cert', attribute_data_map))['value']['bytes_value']
            decoded_certificate_data = base64.b64decode(certificate_data).decode()
            certificates.append(decoded_certificate_data)
        except KeyError:
            continue

    if not certificates:
        print("No certificates found.")
        return


    if output_format == "console":
        print("%-30s | %-26s | %-26s | %-20s | %-60s | %-40s " % ("File", "Not Before", "Not After", "Certificate Status", "Subject", "Issuer" ))
        print("%-30s | %-26s | %-26s | %-20s | %-60s | %-40s " % ("------------------------------", "--------------------------", "--------------------------", "--------------------", "-------------------------------------------", "----------------------------------------"))
        for i, cert in enumerate(certificates):
            if not cert.strip():  # Check if cert is empty or only contains whitespace
               print(f"Skipping empty certificate {i+1}")
               continue           
            try:
                openssl_output = subprocess.check_output(["openssl", "x509", "-noout", "-dates", "-subject", "-issuer", "-nameopt", "RFC2253"], input=cert.encode()).decode("utf-8")
                not_before = openssl_output.split("notBefore=")[1].split("\n")[0]
                not_after = openssl_output.split("notAfter=")[1].split("\n")[0]
                subject_parts = openssl_output.splitlines()
                for line in subject_parts:
                    if line.startswith("subject="):
                        subject = line.split("subject=")[1].strip()
                        subject_cn = None
                        subject_o = None
                        subject_ou = None
                        parts = subject.replace("CN=", "CN=").replace(",", ", ").split(", ")
                        for part in parts:
                            if part.startswith("CN="):
                                subject_cn = part.split("=")[1]
                            elif part.startswith("O="):
                                subject_o = part.split("=")[1]
                            elif part.startswith("OU="):
                                subject_ou = part.split("=")[1]
                        break
                else:
                    subject_cn = "Unknown"
                    subject_o = "Unknown"
                    subject_ou = "Unknown"
    
                issuer_parts = openssl_output.splitlines()
                for line in issuer_parts:
                    if line.startswith("issuer="):
                        issuer = line.split("issuer=")[1].strip()
                        issuer_o = None
                        issuer_cn = None
                        parts = issuer.replace("SN=", "").replace(",", ", ").split(", ")
                        for part in parts:
                            if part.startswith("O="):
                                issuer_o = part.split("=")[1]
                            elif part.startswith("CN="):
                                issuer_cn = part.split("=")[1]
                        break
                else:
                    print("Issuer O: Unknown")
                    print("Issuer CN: Unknown")
    
                not_before_date = datetime.datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                not_after_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                current_date = datetime.datetime.now()
    
                if current_date < not_before_date:
                    status = "Not yet valid"
                elif current_date > not_after_date:
                    status = "Expired"
                else:
                    status = "Valid"
    
                subject_str = f"O={subject_o}, CN={subject_cn}"
                if subject_ou:
                    subject_str += f", OU={subject_ou}"
                issuer_str = f"O={issuer_o}, CN={issuer_cn}"
    
                print("%-30s | %-26s | %-26s | %-20s | %-60s | %-40s " % (f" {i+1}", not_before, not_after, status, subject_str, issuer_str))
            except subprocess.CalledProcessError as e:
                print(f"Error processing certificate {i+1}")
                continue   
    elif output_format == "html":
        html_output = """
<html>
  <head>
    <title>Certificate Status</title>
    <style>
      table {
        border-collapse: collapse;
      }
      th, td {
        border: 1px solid #ddd;
        padding: 8px;
        text-align: left;
      }
    </style>
  </head>
  <body>
    <h1>Certificate Status</h1>
    <table>
      <tr>
        <th>File</th>
        <th>Not Before</th>
        <th>Not After</th>
        <th>Certificate Status</th>
        <th>Subject</th>
        <th>Issuer</th>
      </tr>
      <tr>
        <td colspan="6"><hr /></td>
      </tr>
"""

        for i, cert in enumerate(certificates):
            error_occurred = False
            try:
                openssl_output = subprocess.check_output(["openssl", "x509", "-noout", "-dates", "-subject", "-issuer", "-nameopt", "RFC2253"], input=cert.encode()).decode("utf-8")
                not_before = openssl_output.split("notBefore=")[1].split("\n")[0]
                not_after = openssl_output.split("notAfter=")[1].split("\n")[0]
      
                subject_parts = openssl_output.splitlines()

                for line in subject_parts:
                    if line.startswith("subject="):
                        subject = line.split("subject=")[1].strip()
                        subject_cn = None
                        subject_o = None
                        subject_ou = None
                        parts = subject.replace("CN=", "CN=").replace(",", ", ").split(", ")
                        for part in parts:
                            if part.startswith("CN="):
                                subject_cn = part.split("=")[1]
                            elif part.startswith("O="):
                                subject_o = part.split("=")[1]
                            elif part.startswith("OU="):
                                subject_ou = part.split("=")[1]
                        break
                else:
                    subject_cn = "Unknown"
                    subject_o = "Unknown"
                    subject_ou = "Unknown"

                issuer_parts = openssl_output.splitlines()
                for line in issuer_parts:
                    if line.startswith("issuer="):
                        issuer = line.split("issuer=")[1].strip()
                        issuer_o = None
                        issuer_cn = None
                        parts = issuer.replace("SN=", "").replace(",", ", ").split(", ")
                        for part in parts:
                            if part.startswith("O="):
                                issuer_o = part.split("=")[1]
                            elif part.startswith("CN="):
                                issuer_cn = part.split("=")[1]
                        break
                else:
                    issuer_o = "Unknown"
                    issuer_cn = "Unknown"

                not_before_date = datetime.datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                not_after_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                current_date = datetime.datetime.now()

                if current_date < not_before_date:
                    status = "Not yet valid"
                elif current_date > not_after_date:
                    status = "Expired"
                else:
                    status = "Valid"

                subject_str = f"O={subject_o}, CN={subject_cn}"
                if subject_ou:
                    subject_str += f", OU={subject_ou}"
                issuer_str = f"O={issuer_o}, CN={issuer_cn}"

            except subprocess.CalledProcessError as e:
                print(f"Error processing certificate {i+1}")
                error_occurred = True
                not_before = "Error"
                not_after = "Error"
                status = "Error"
                subject_str = "Error"
                issuer_str = "Error"

            if error_occurred:
                html_output += f"""
      <tr>
        <td> {i+1}</td>
        <td>{not_before}</td>
        <td>{not_after}</td>
        <td>{status}</td>
        <td>{subject_str}</td>
        <td>{issuer_str}</td>
      </tr>
"""
            else:
                html_output += f"""
      <tr>
        <td> {i+1}</td>
        <td>{not_before}</td>
        <td>{not_after}</td>
        <td>{status}</td>
        <td>{subject_str}</td>
        <td>{issuer_str}</td>
      </tr>
"""

        html_output += """
    </table>
  </body>
</html>
"""

        html_pages_dir = "html_pages"
        if not os.path.exists(html_pages_dir):
            os.makedirs(html_pages_dir)
        filename = "certificate_status_idf.html"
        filepath = os.path.join(html_pages_dir, filename)
        print("\n")
        print(f"The HTML file location for IDF Certs (MSP): {filepath}")
        with open(filepath, "w") as f:
            f.write(html_output)


def main():
    generate_certificate_status_idf(output_format="console")
    generate_certificate_status_system(output_format="console")
    # generate_certificate_status_idf(output_format="html") # Output in HTML Format 
    # generate_certificate_status_system(output_format="html") # Output in HTML Format 

if __name__ == "__main__":
    main()            
