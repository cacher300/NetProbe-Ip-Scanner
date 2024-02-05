from flask import Flask, render_template, request, redirect, url_for, send_file
import subprocess
from sql_setup import get_db_data
import sqlite3
import csv
app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        scan_type = request.form.get('scan_type')
        threads = int(request.form.get('threads'))
        ports = request.form.get('ports')
        ip_range = request.form.get('ip_range')

        ip_range = '' if ip_range is None else ip_range

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

        print(f"Scan Type: {scan_type}, Threads: {threads}, IP Range: {ip_range}")
        subprocess.run(['python', 'backend.py', scan_type, str(threads), ip_range, str(length)] + port_list, check=True)

        return redirect(url_for('table'))

    return render_template('index.html')


@app.route('/table')
def table():
    data = get_db_data()
    return render_template('table.html', data=data)


@app.route('/download')
def download():
    conn = sqlite3.connect('scan_results.db')
    cursor = conn.cursor()

    query = """
    SELECT ip_addresses.id, ip_addresses.ip_address, group_concat(open_ports.port, ', ') as ports
    FROM ip_addresses
    LEFT JOIN open_ports ON ip_addresses.id = open_ports.ip_id
    GROUP BY ip_addresses.id
    """
    cursor.execute(query)
    data = cursor.fetchall()

    csv_file_path = 'ip_ports_export.csv'

    with open(csv_file_path, 'w', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(['ID', 'IP Address', 'Ports Open'])
        for row in data:
            csv_writer.writerow(row)

    conn.close()

    return send_file(csv_file_path, as_attachment=True, download_name='ip_ports_export.csv')


@app.route('/wipe')
def wipe_database():
    conn = sqlite3.connect('scan_results.db')
    cursor = conn.cursor()

    cursor.execute("DELETE FROM open_ports")

    cursor.execute("DELETE FROM ip_addresses")

    conn.commit()
    conn.close()

    return redirect(url_for('table'))


if __name__ == '__main__':
    app.run(debug=True)
