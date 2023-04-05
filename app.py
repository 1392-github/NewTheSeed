from flask import Flask, render_template, request
app = Flask(__name__)
@app.route("/master_test")
def master():
    return render_template("master.html", wiki_title = "TheWiki", wiki_name = "TheWiki")
app.run(debug=True)
