import os
import html
import urllib.parse

from flask import Flask, redirect, url_for, request

from passthesalt import (
    Algorithm,
    Encrypted,
    Generatable,
    Login,
    Master,
    PassTheSalt,
    Secret,
)

app = Flask(__name__)

@app.route('/')
def index():
    result = '<html><table>'

    pts = PassTheSalt().from_path(os.path.expanduser('~/.passthesalt'))

    for label in sorted(pts.labels()):
        display = pts.get(label).display()
        label, kind, modified = display[:3]
        salt = ""
        if len(display) > 3:
            salt = display[3]

        url = url_for('get') + '?label=' + urllib.parse.quote_plus(label)

        result += f'''<tr>
    <td><a href="{url}">{label}</a></td>
    <td>{kind}</td>
    <td>{modified}</td>
    <td>{salt}</td>
  </tr>
'''
    result += '</table></html>'
    return result


@app.route("/get", methods=['GET', 'POST'])
def get():
    label = request.args["label"]

    if request.method == 'POST':
        master_key = request.form['master_key']
        pts = PassTheSalt().from_path(os.path.expanduser('~/.passthesalt')).with_master(master_key)
        try:
            secret = html.escape(pts.get(label).get())
        except Exception as e:
            e = html.escape(repr(e))
            return f'<html><b>Error:&nbsp</b>{e}</html>'
        return f'<html><h3>{secret}</h3></html>'

    label = urllib.parse.quote_plus(label)

    form = f'''
<form action="/get?label={label}" method="post">
 <ul>
  <li>
    <label for="label">Label:</label>
    <input type="text" id="label" name="label" value="{label}">
  </li>
  <li>
    <label for="master_key">Master Key:</label>
    <input type="password" id="master_key" name="master_key">
  </li>
  <li class="button">
    <button type="submit">Fetch</button>
  </li>

 </ul>
</form>

'''

    return form


if __name__ == "__main__":
    app.run(host = '0.0.0.0', port = '8000')
