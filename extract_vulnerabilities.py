import xml.etree.ElementTree as ET


def extract_vulnerabilities(file_path):
    # Parse the XML file
    tree = ET.parse(file_path)
    root = tree.getroot()

    # List to store extracted vulnerabilities
    vulnerabilities = []

    # Find all results
    for result in root.findall(".//result"):
        vuln_info = {}
        # Extract basic details
        vuln_info["name"] = result.findtext("name")
        vuln_info["severity"] = result.findtext("severity")
        vuln_info["threat"] = result.findtext("threat")
        vuln_info["port"] = result.findtext("port")

        # Extract CVEs if present
        cves = []
        for ref in result.findall(".//ref[@type='cve']"):
            cves.append(ref.get("id"))
        vuln_info["cves"] = cves

        # Append the extracted data to the list
        vulnerabilities.append(vuln_info)

    return vulnerabilities


file_path = "Report.xml"
vulnerabilities_data = extract_vulnerabilities(file_path)

# Print the extracted vulnerabilities
for vuln in vulnerabilities_data:
    print(f"Name: {vuln['name']}")
    print(f"Severity: {vuln['severity']}")
    print(f"Threat: {vuln['threat']}")
    print(f"Port: {vuln['port']}")
    print(f"CVEs: {', '.join(vuln['cves']) if vuln['cves'] else 'None'}")
    print("-" * 40)
