from flask import Flask, render_template, request, redirect, url_for
import subprocess
from sql_setup import get_db_data
app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        scan_type = request.form.get('scan_type')
        threads = int(request.form.get('threads'))
        ports = request.form.get('ports')
        ip_range = request.form.get('ip_range')

        ip_range = '' if ip_range is None else ip_range

        port_list = ports.split(',')
        port_list = [port.strip() for port in port_list]
        length = len(port_list)

        print(f"Scan Type: {scan_type}, Threads: {threads}, IP Range: {ip_range}")
        subprocess.run(['python', 'backend.py', scan_type, str(threads), ip_range, str(length)] + port_list, check=True)

        return redirect(url_for('table'))

    return render_template('index.html')


@app.route('/table')
def table():
    data = get_db_data()
    return render_template('table.html', data=data)


if __name__ == '__main__':
    app.run(debug=True)
