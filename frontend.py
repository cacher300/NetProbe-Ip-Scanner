from flask import Flask, send_from_directory, render_template
import os
import sys

app = Flask(__name__,
            template_folder=os.path.join(getattr(sys, '_MEIPASS', os.path.abspath(os.path.dirname(__file__))),
                                         'templates'))


@app.route('/')
def home():
    return render_template('index.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0')