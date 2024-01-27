from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        scan_type = request.form.get('scan_type')
        threads = int(request.form.get('threads'))
        ip_range = request.form.get('ip_range') if scan_type == 'ip_range' else None

        print(f"Scan Type: {scan_type}, Threads: {threads}, IP Range: {ip_range}")

        return redirect(url_for('index'))

    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)
