from flask import Flask, render_template, request, redirect, url_for
import subprocess
app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        scan_type = request.form.get('scan_type')
        threads = int(request.form.get('threads'))
        ip_range = request.form.get('ip_range')
        ip_range = '' if ip_range is None else ip_range

        print(f"Scan Type: {scan_type}, Threads: {threads}, IP Range: {ip_range}")
        subprocess.run(['python', 'backend.py', scan_type, str(threads), ip_range], check=True)

        return redirect(url_for('index'))

    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)
