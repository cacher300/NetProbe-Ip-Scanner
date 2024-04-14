from flask import Flask, render_template, request, redirect, url_for, send_file
import subprocess
from local_sql_setup import get_local_db_data
from world_sql_setup import get_world_db_data
import sqlite3
import csv
from ipaddress import ip_network, IPv4Address
import tempfile
import sys
app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        scan_type = request.form.get('scan_type')
        threads = int(request.form.get('threads'))
        ports = request.form.get('ports')
        scan_target = request.form.get('ip_range')

        initial_list = ports.split(',')
        port_list = []

        for port in initial_list:
            if '-' in port:
                start, end = map(int, port.split('-'))
                port_list.extend(range(start, end + 1))
            else:
                port_list.append(int(port))
        length = len(port_list)

        port_list = [str(port) for port in port_list]

        print(f"Scan Type: {scan_type}, Threads: {threads}, Scan Target: {scan_target}")

        if scan_type == 'local_network':
            subprocess.run([sys.executable, 'local.py', scan_type, str(threads), 'localhost', str(length)] + port_list,
                           check=True)
            return redirect(url_for('local_table'))

        elif scan_type == 'ip_range':
            ip_range_list = scan_target.split('-')
            if len(ip_range_list) == 2:  # If the IP range is provided in start-end format
                ip_start = int(IPv4Address(ip_range_list[0].strip()))
                ip_end = int(IPv4Address(ip_range_list[1].strip()))

                ip_range = [str(IPv4Address(ip)) for ip in range(ip_start, ip_end + 1)]
            else:  # If the IP range is provided in CIDR notation
                ip_range = [str(ip) for ip in ip_network(scan_target).hosts()]

            with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
                temp_file.write('\n'.join(ip_range))

            # Construct the command to pass to subprocess.run
            command = ['python', 'world.py', scan_type, str(threads), str(len(port_list)), temp_file.name] + port_list

            # Call subprocess.run with the constructed command
            subprocess.run(command, check=True)

            # Delete the temporary file
            temp_file.close()

            return redirect(url_for('world_table'))

    return render_template('index.html')


@app.route('/world_table')
def world_table():
    data = get_world_db_data()
    return render_template('world_table.html', data=data)


@app.route('/local_table')
def local_table():
    data = get_local_db_data()
    return render_template('local_table.html', data=data)


@app.route('/world_download')
def world_download():
    # Connect to the database
    conn = sqlite3.connect('world_scan_results.db')
    cursor = conn.cursor()

    # Updated SQL query to fetch all relevant data
    query = """
    SELECT ip_addresses.id, ip_addresses.ip_address, group_concat(open_ports.port, ', ') as ports,
           ip_addresses.location,  ip_addresses.ip_lookup
    FROM ip_addresses
    LEFT JOIN open_ports ON ip_addresses.id = open_ports.ip_id
    GROUP BY ip_addresses.id
    """
    cursor.execute(query)
    data = cursor.fetchall()

    # Path where the CSV file will be saved
    csv_file_path = 'ip_ports_export.csv'

    # Writing to the CSV file
    with open(csv_file_path, 'w', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(['ID', 'IP Address', 'Ports Open', 'Location', 'IP Lookup'])
        for row in data:
            csv_writer.writerow(row)

    # Close the database connection
    conn.close()

    # Return the CSV file as a downloadable response
    return send_file(csv_file_path, as_attachment=True, download_name='ip_ports_export.csv')


@app.route('/local_download')
def local_download():
    conn = sqlite3.connect('local_scan_results.db')
    cursor = conn.cursor()

    query = """
    SELECT ip_addresses.id, ip_addresses.ip_address, GROUP_CONCAT(open_ports.port, ', ') as ports,
            ip_addresses.name, ip_addresses.type, ip_addresses.os, ip_addresses.mac_address, ip_addresses.status
    FROM ip_addresses
    LEFT JOIN open_ports ON ip_addresses.id = open_ports.ip_id
    GROUP BY ip_addresses.id
    
    """
    cursor.execute(query)
    data = cursor.fetchall()
    conn.close()

    csv_file_path = 'ip_ports_export.csv'

    with open(csv_file_path, 'w', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(['ID', 'IP Address', 'Ports Open', 'Name', "Type", 'OS', 'Mac Address', 'Status'])
        for row in data:
            csv_writer.writerow(row)

    return send_file(csv_file_path, as_attachment=True, download_name='ip_ports_export.csv')


@app.route('/local_wipe')
def local_wipe_database():
    conn = sqlite3.connect('local_scan_results.db')
    cursor = conn.cursor()

    cursor.execute("DELETE FROM open_ports")

    cursor.execute("DELETE FROM ip_addresses")

    conn.commit()
    conn.close()

    return redirect(url_for('local_table'))


@app.route('/world_wipe')
def world_wipe_database():
    conn = sqlite3.connect('world_scan_results.db')
    cursor = conn.cursor()

    cursor.execute("DELETE FROM open_ports")

    cursor.execute("DELETE FROM ip_addresses")

    conn.commit()
    conn.close()

    return redirect(url_for('world_table'))


if __name__ == '__main__':
    app.run(debug=True)
