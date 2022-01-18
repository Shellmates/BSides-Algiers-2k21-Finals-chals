import os
from flask import Flask, flash, request, redirect, render_template
from dotenv import load_dotenv
from lxml.etree import XMLParser, fromstring as validate_xml, XMLSyntaxError

load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY")
app.config["DEBUG"] = os.getenv("FLASK_ENV") == "development"
FLAG = os.getenv("FLAG")

DEFAULT_ENCODING = "UTF-8"
XML_TEMPLATE_FUNC = \
'''\
<?xml version="1.0" encoding="{encoding}"?>
<root>
\t<name>{name}</name>
</root>
'''.format
MAX_ENCODING_LENGTH = 11

xml_parser = XMLParser(no_network=True, load_dtd=True, huge_tree=False)

def xml_name(xml_payload):
    xml_parser.feed(xml_payload)
    xml_data = xml_parser.close()
    result = xml_data.xpath("./name/text()")
    name = result[0] if len(result) > 0 else ""
    return name

# Routes

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return render_template("index.html")

    name = request.form.get("name")
    encoding = request.form.get("encoding") or DEFAULT_ENCODING
    if not name:
        flash("Name not specified", "red")
        return redirect("/")
    if len(encoding) > MAX_ENCODING_LENGTH:
        flash("Encoding too long", "red")
        return redirect("/")

    xml_string = ""
    parsed_name = ""
    try:
        xml_string = XML_TEMPLATE_FUNC(name=name, encoding=encoding)
        parsed_name = xml_name(xml_string)
    except Exception as e:
        flash(f"{e.__class__.__name__}", "red")

    return render_template("index.html", name=parsed_name, xml_string=xml_string)

# Error handling

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("500.html"), 500
