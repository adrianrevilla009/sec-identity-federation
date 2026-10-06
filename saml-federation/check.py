"""Offline check of the SAML lab config; with --live also fetches the IdP metadata from a running compose stack."""
import json, pathlib, re, sys
from urllib import request
from xml.etree import ElementTree as ET

here = pathlib.Path(__file__).parent
realm = json.loads((here / "orders-realm.json").read_text())
sp = next(c for c in realm["clients"] if c["protocol"] == "saml")
assert sp["redirectUris"] == [sp["attributes"]["saml_assertion_consumer_url_post"]], "ACS must be the only redirect URI"
assert sp["attributes"]["saml.assertion.signature"] == "true", "assertions must be signed"
compose = (here / "compose.yaml").read_text()
assert re.search(r"keycloak:\d+\.\d+\.\d+", compose), "Keycloak image must be pinned"
print("config ok: SP", sp["clientId"], "-> ACS", sp["redirectUris"][0])

if "--live" in sys.argv:
    xml = request.urlopen("http://localhost:8080/realms/orders/protocol/saml/descriptor").read()
    ns = {"md": "urn:oasis:names:tc:SAML:2.0:metadata"}
    sso = ET.fromstring(xml).find(".//md:IDPSSODescriptor/md:SingleSignOnService", ns)
    assert sso is not None, "no SSO endpoint in IdP metadata"
    print("live ok: IdP SSO endpoint", sso.get("Location"))
print("OK")
