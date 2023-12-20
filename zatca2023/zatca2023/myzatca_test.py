import frappe
# frappe.init(site="husna.erpgulf.com")
# frappe.connect()
import os 
from subprocess import call
import subprocess
import requests
import json
from datetime import datetime
import ecdsa
from ecdsa import SigningKey, SECP256k1
import binascii
from signxml import XMLSigner, XMLVerifier
import xml.etree.ElementTree as ET
from xml.etree import ElementTree
from OpenSSL import crypto
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from base64 import b64encode, b64decode
from cryptography.hazmat.backends.openssl import backend as openssl_backend                      
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import serialization
import base64
import hashlib
from frappe import enqueue
from frappe.utils.file_manager import save_url
from fatoora import Fatoora
import sys
import time
from frappe.utils import now
from frappe.utils.data import add_to_date, get_time, getdate
import OpenSSL
import chilkat2
from lxml import etree
import uuid
import re
from frappe.utils.file_manager import get_content_hash

def send_invoice_for_clearance_normal(uuid,invoiceHash):
                    signedXmlFilePath = "/opt/oxy/frappe-bench/sites/signedXML_withQR.xml"
                    token,secret = create_security_token_from_csr()
                    with open(signedXmlFilePath, "r") as file:
                        xml = file.read().lstrip()
                        base64_encoded = base64.b64encode(xml.encode("utf-8"))
                        base64_decoded = base64_encoded.decode("utf-8")
                    url = "https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal/compliance/invoices"
                    payload = json.dumps({
                    "invoiceHash": invoiceHash,
                    "uuid": uuid,
                    "invoice": base64_decoded
                    })
                    headers = { 
                        'accept': 'application/json',
                        'Accept-Language': 'en',
                        'Accept-Version': 'V2',
                        'Authorization': "Basic VFVsSlJERnFRME5CTTNsblFYZEpRa0ZuU1ZSaWQwRkJaVFJUYUhOMmVXNDNNREo1VUhkQlFrRkJRamRvUkVGTFFtZG5jV2hyYWs5UVVWRkVRV3BDYWsxU1ZYZEZkMWxMUTFwSmJXbGFVSGxNUjFGQ1IxSlpSbUpIT1dwWlYzZDRSWHBCVWtKbmIwcHJhV0ZLYXk5SmMxcEJSVnBHWjA1dVlqTlplRVo2UVZaQ1oyOUthMmxoU21zdlNYTmFRVVZhUm1ka2JHVklVbTVaV0hBd1RWSjNkMGRuV1VSV1VWRkVSWGhPVlZVeGNFWlRWVFZYVkRCc1JGSlRNVlJrVjBwRVVWTXdlRTFDTkZoRVZFbDVUVVJaZUUxNlJURk5la1V3VG14dldFUlVTVEJOUkZsNFRXcEZNVTE2UlRCT2JHOTNVMVJGVEUxQmEwZEJNVlZGUW1oTlExVXdSWGhFYWtGTlFtZE9Wa0pCYjFSQ1YwWnVZVmQ0YkUxU1dYZEdRVmxFVmxGUlRFVjNNVzlaV0d4b1NVaHNhRm95YUhSaU0xWjVUVkpKZDBWQldVUldVVkZFUlhkcmVFMXFZM1ZOUXpSM1RHcEZkMVpxUVZGQ1oyTnhhR3RxVDFCUlNVSkNaMVZ5WjFGUlFVTm5Ua05CUVZSVVFVczViSEpVVm10dk9YSnJjVFphV1dOak9VaEVVbHBRTkdJNVV6UjZRVFJMYlRkWldFb3JjMjVVVm1oTWEzcFZNRWh6YlZOWU9WVnVPR3BFYUZKVVQwaEVTMkZtZERoREwzVjFWVms1TXpSMmRVMU9ielJKUTB0cVEwTkJhVmwzWjFselIwRXhWV1JGVVZOQ1ozcERRbWRMVWl0TlNIZDRTRlJCWWtKblRsWkNRVkZOUmtSRmRHRkhSalZaV0hkNVRGUkplazVJZDNwTVZFVjRUV3BOZWsxU09IZElVVmxMUTFwSmJXbGFVSGxNUjFGQ1FWRjNVRTE2VFhoTlZGbDVUMFJaTlU1RVFYZE5SRUY2VFZFd2QwTjNXVVJXVVZGTlJFRlJlRTFVUVhkTlVrVjNSSGRaUkZaUlVXRkVRV2hoV1ZoU2FsbFRRWGhOYWtWWlRVSlpSMEV4VlVWRWQzZFFVbTA1ZGxwRFFrTmtXRTU2WVZjMWJHTXpUWHBOUWpCSFFURlZaRVJuVVZkQ1FsTm5iVWxYUkRaaVVHWmlZa3RyYlZSM1QwcFNXSFpKWWtnNVNHcEJaa0puVGxaSVUwMUZSMFJCVjJkQ1VqSlpTWG8zUW5GRGMxb3hZekZ1WXl0aGNrdGpjbTFVVnpGTWVrSlBRbWRPVmtoU09FVlNla0pHVFVWUFoxRmhRUzlvYWpGdlpFaFNkMDlwT0haa1NFNHdXVE5LYzB4dWNHaGtSMDVvVEcxa2RtUnBOWHBaVXpsRVdsaEtNRkpYTlhsaU1uaHpUREZTVkZkclZrcFViRnBRVTFWT1JreFdUakZaYTA1Q1RGUkZkVmt6U25OTlNVZDBRbWRuY2tKblJVWkNVV05DUVZGVFFtOUVRMEp1VkVKMVFtZG5ja0puUlVaQ1VXTjNRVmxhYVdGSVVqQmpSRzkyVEROU2VtUkhUbmxpUXpVMldWaFNhbGxUTlc1aU0xbDFZekpGZGxFeVZubGtSVloxWTIwNWMySkRPVlZWTVhCR1lWYzFNbUl5YkdwYVZrNUVVVlJGZFZwWWFEQmFNa1kyWkVNMWJtSXpXWFZpUnpscVdWZDRabFpHVG1GU1ZXeFBWbXM1U2xFd1ZYUlZNMVpwVVRCRmRFMVRaM2hMVXpWcVkyNVJkMHQzV1VsTGQxbENRbEZWU0UxQlIwZElNbWd3WkVoQk5reDVPVEJqTTFKcVkyMTNkV1Z0UmpCWk1rVjFXakk1TWt4dVRtaE1NamxxWXpOQmQwUm5XVVJXVWpCUVFWRklMMEpCVVVSQloyVkJUVUl3UjBFeFZXUktVVkZYVFVKUlIwTkRjMGRCVVZWR1FuZE5RMEpuWjNKQ1owVkdRbEZqUkVGNlFXNUNaMnR5UW1kRlJVRlpTVE5HVVc5RlIycEJXVTFCYjBkRFEzTkhRVkZWUmtKM1RVTk5RVzlIUTBOelIwRlJWVVpDZDAxRVRVRnZSME5EY1VkVFRUUTVRa0ZOUTBFd1owRk5SVlZEU1ZGRVQxQXdaakJFY21oblpVUlVjbFpNZEVwMU9HeFhhelJJU25SbFkyWTFabVpsVWt4blpVUTRZMlZWWjBsblpFSkNUakl4U1RNM2FYTk5PVlZ0VTFGbE9IaFNjRWh1ZDA5NFNXYzNkMDR6V1RKMlZIQnpVR2hhU1QwPTpFcGo2OUdoOFRNTXpZZktsdEx2MW9tWktyaWUwc1A2TEF2YW1iUUZIVGd3PQ==",
                        'Content-Type': 'application/json'}
                    settings = frappe.get_doc('Saudi Zatca settings')
                    settings.pih = invoiceHash
                    settings.save()
                    response = requests.request("POST", url, headers=headers, data=payload)
                    print(response.text)
                    try:
                        response = requests.request("POST", url, headers=headers, data=payload)
                        return response.text , get_Clearance_Status(response)
                    except Exception as e:    
                        print(str(e)) 
                        return "error","NOT_CLEARED"
                        sys.exit()
                    
def get_signed_xml_invoice_for_clearance():
                # digest value clearance 
                signedXmlFilePath = "/opt/oxy/frappe-bench/sites/signedXml.xml"
                xmlSigned = chilkat2.Xml()
                success = xmlSigned.LoadXmlFile(signedXmlFilePath)
                if (success == False):
                    print(xmlSigned.LastErrorText)
                    sys.exit()
                sbDigestValue = chilkat2.StringBuilder()
                success = xmlSigned.GetChildContentSb("ext:UBLExtensions|ext:UBLExtension|ext:ExtensionContent|sig:UBLDocumentSignatures|sac:SignatureInformation|ds:Signature|ds:SignedInfo|ds:Reference[0]|ds:DigestValue",sbDigestValue)
                if (success == False):
                    print("Failed to get DigestValue from signed XML.")
                    sys.exit()
                return sbDigestValue, xmlSigned, signedXmlFilePath

def create_security_token_from_csr():
                #Creating and returning token, secret 
                try:
                        with open("mycscsr2.csr", "r") as f:
                            csr_contents = f.read()
                except Exception as e:
                        print(str(e))
                base64csr = base64.b64encode(csr_contents.encode("utf-8")).decode("utf-8")
                url = "https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal/compliance"
                payload = json.dumps({
                "csr": base64csr
                })
                headers = {
                'accept': 'application/json',
                'OTP': '123345',
                'Accept-Version': 'V2',
                'Content-Type': 'application/json',
                'Cookie': 'TS0106293e=0132a679c07382ce7821148af16b99da546c13ce1dcddbef0e19802eb470e539a4d39d5ef63d5c8280b48c529f321e8b0173890e4f'
                }
                response = requests.request("POST", url, headers=headers, data=payload)
                data=json.loads(response.text)
                return data["binarySecurityToken"],  data["secret"]

def  get_Issue_Time(invoice_number):
                #issuing the posting time 
                doc = frappe.get_doc("Sales Invoice", invoice_number)
                time = get_time(doc.posting_time)
                issue_time = time.strftime("%H:%M:%S")
                return issue_time

def get_Tax_for_Item(full_string,item):
                data = json.loads(full_string)
                tax_percentage=data.get(item,[0,0])[0]
                tax_amount = data.get(item, [0, 0])[1]
                return tax_amount,tax_percentage

def invoice_uuid(invoice_number):
                #uuid saving for invoice which is unique for all invoice
                invoice= frappe.get_doc("Sales Invoice",invoice_number)
                invoice.custom_uuid = str(uuid.uuid1())
                invoice.save()
                return invoice.custom_uuid   

def certificate_load():
                # with open('rsacertificate.pem', 'r') as cert_file:
                with open('procerti.crt', 'r') as cert_file:
                    certificate_content = cert_file.read()
                    start_marker = "-----BEGIN CERTIFICATE-----"
                    end_marker = "-----END CERTIFICATE-----"
                    start_index = certificate_content.find(start_marker) + len(start_marker)
                    end_index = certificate_content.find(end_marker)
                    cert= certificate_content[start_index:end_index].strip()
                    cert1 = cert.replace("\n", "")
                    cert2= crypto.load_certificate(crypto.FILETYPE_PEM, certificate_content)
                    issuer_name_components = cert2.get_issuer().get_components()
                    issuer_str = ", ".join([f"{key.decode('utf-8')}={value.decode('utf-8')}" for key, value in issuer_name_components])
                    serial = cert2.get_serial_number()
                    signature_val= cert2.to_cryptography().signature
                    print(signature_val)
                    signature_hex = binascii.hexlify(signature_val).decode('utf-8')
                    return cert1, issuer_str,serial,signature_hex
                
def signature_value_and_digestvalue():
                    certdigestval="OGVjNTBlZThjZWM5MGUwODI5NmUzYmIyZDNkZWFjOTNjODM1YWEyNjk2Zjg3MTc2N2FiNzUwMWU0ZDBiMGM1Mw=="
                    digestvalue1="3ut6eDuWN8aRdtP7TUie1vfLJgYaFQ205sLoQFeSmAs="        
                    digestvalue2="NGE1YjY4MWQzYmIxMWQ4ODI3Y2ZiNWQ2OTEwZmUxZTZiZWZkNWYzMDg0ZWFjYjMwM2UzMDFmZmI4NzIxYTkyOQ=="         
                    return digestvalue1,digestvalue2,certdigestval

def get_ICV_code(invoice_number):
                    icv_code = + int(''.join(filter(str.isdigit, invoice_number))) 
                    return icv_code

def get_digest_value(cert2):
                    public_key = cert2.public_key()
            # Calculate the digest using SHA-256
                    digest_algorithm = hashes.SHA256()
                    digest = public_key.fingerprint(digest_algorithm) 
                    digest_hex = digest.hex()
                    print(f"The digest value (SHA-256) of the certificate is: {digest_hex}") 
                
def get_Actual_Value_And_Rendering(invoice_number):
                cert1, issuer_str,serial,signature_hex = certificate_load()
                digestvalue1,digestvalue2,certdigestval = signature_value_and_digestvalue()
                e_invoice_items = []
                settings=frappe.get_doc('Saudi Zatca settings')
                doc = frappe.get_doc("Sales Invoice", invoice_number) 
                company_doc = frappe.get_doc("Company", doc.company)
                customer_doc= frappe.get_doc("Customer",doc.customer)
                for item in doc.items:
                    item_tax_amount,item_tax_percentage =  get_Tax_for_Item(doc.taxes[0].item_wise_tax_detail,item.item_code)
                    item_data = {
                        "qty": item.qty,
                        "amount": item.amount,
                        "item_tax_percentage" : item_tax_percentage,
                        "item_character":doc.custom_item_character,
                        "item_tax_amount":item_tax_amount,
                        "base_net_amount": item.amount + item_tax_amount,
                        "item_code": item.item_code,
                        "price_list_rate": item.price_list_rate, }
                    e_invoice_items.append(item_data)
                context = { "doc": {
                                # "issuer":issuer_str,
                                # "time":"2023-11-09T10:38:39Z",
                                # "serial":serial,
                                # "digsetval1": digestvalue1,
                                # "digestval2": digestvalue2,
                                # # "signatureval":signature_hex,
                                # "certificate":cert1,
                                "document_id":doc.custom_document_id,
                                "icv_code" : get_ICV_code(invoice_number),
                                "acccustid":customer_doc.custom_accounting_customer_id,
                                "accsupid":company_doc.custom_accounting_supplier_party_id,
                                "invoice_number":doc.custom_invoice,
                                "invoice_type_code":doc.custom_invoice_type_code,
                                "payment_code":doc.custom_payment_code,
                                "lineCount":doc.custom_total_no_of_line,
                                "e_invoice_items": e_invoice_items,
                                "company_tax_id":company_doc.tax_id,
                                "uuid":doc.custom_uuid,
                                "posting_date": doc.posting_date,
                                "qr_code": "GsiuvGjvchjbFhibcDhjv1886G",
                                "posting_time":get_Issue_Time(invoice_number),
                                "company": doc.company,
                                "currency":doc.currency,
                                "customer": doc.customer,
                                "custom_taxcateg_id":doc.custom_taxcateg_id,
                                "total": doc.base_net_total,                                       
                                "pih": settings.pih,
                                "total_taxes_and_charges": doc.base_total_taxes_and_charges,
                                "total": doc.total,
                                "grand_total": doc.grand_total,
                                "tax_rate":doc.taxes[0].rate,
                                "company_address_data":{
                                            "sub":company_doc.custom_sub,
                                            "building_no": company_doc.custom_build_no,
                                            "street": company_doc.custom_street,
                                            "city":company_doc.custom_city,
                                            "pincode": company_doc.custom_pincode,
                                            "state": company_doc.custom_state,
                                            "plot_id_no": company_doc.custom_plot_id_no,
                                            "country":company_doc.custom_country_name},
                                "customer_address_data": {
                                            "street": customer_doc.custom_street,
                                            "building_no": customer_doc.custom_building_no,
                                            "sub":customer_doc.custom_sub,
                                            "city":customer_doc.custom_city,
                                            "pincode": customer_doc.custom_pincode,
                                            "state": customer_doc.custom_state,
                                            "plot_id_no":customer_doc.custom_plot_id_no,
                                            "country":customer_doc.custom_country},}}
                invoice_xml = frappe.render_template("saudi_phase2_api/saudi_phase2_api/e_test.xml", context)
                print("invoice_xml is",invoice_xml)
                hash_value =hashlib.sha256(invoice_xml.encode('utf-8')).hexdigest()
                # print(hash_value)
                hash_bytes = hash_value.encode('utf-8')
                base64_encoded_hash_value = base64.b64encode(hash_bytes)
                base64_decod_hash_value= base64_encoded_hash_value.decode("utf-8")
                # print("Base64 Encoded:", base64_decod_hash_value)
                frappe.msgprint(frappe.session.user)
                #find the existing XML file and delete it
                try:
                    if frappe.db.exists("File",{ "attached_to_name": doc.name, "attached_to_doctype": doc.doctype }):
                        frappe.db.delete("File",{ "attached_to_name": doc.name, "attached_to_doctype": doc.doctype })
                except Exception as e:
                    frappe.msgprint(frappe.get_traceback())
                fileX = frappe.get_doc(
                    {   "doctype": "File",        
                        "file_type": "xml",  
                        "file_name":  "e_invoice_" + doc.name + ".xml",
                        "attached_to_doctype": doc.doctype,
                        "attached_to_name": doc.name, 
                        "content": invoice_xml,
                        "is_private": 1,
                    })
                try:
                        frappe.msgprint("before insert() ")
                        fileX.insert()
                        frappe.msgprint("inserted) ")
                        # frappe.msgprint("Calculated hash SHA256 : " + hashlib.sha256(invoice_xml.encode('utf-8')).hexdigest())
                        # print("Calculated hash SHA256 : " + hashlib.sha256(invoice_xml.encode('utf-8')).hexdigest())
                        # hash_value =hashlib.sha256(invoice_xml.encode('utf-8')).hexdigest()
                        # print(hash_value)
                        frappe.msgprint("Calculated hash MD5-128 : " + get_content_hash(invoice_xml))
                except Exception as e:
                        frappe.msgprint(frappe.get_traceback())
                #For reference only -   code to get file-name of the XML saved.
                try: 
                    frappe.msgprint(frappe.db.get_value('File', {'attached_to_name': doc.name, 'attached_to_doctype': doc.doctype}, ['file_name']))
                except Exception as e:
                    frappe.msgprint(frappe.get_traceback())
                return invoice_xml,hash_value
                # sys.exit()

def sign_ECDSA_msg(hash_value):#not yet verified
                private_key1 = SigningKey.generate(curve=SECP256k1)
                private_key1_hex = private_key1.to_string().hex()
                # print(private_key1_hex)
                public_key1 = private_key1.get_verifying_key()
                public_key_hex = public_key1.to_string().hex()
                bmessage = hash_value.encode()
                sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key1_hex ), curve=ecdsa.SECP256k1)
                signature = base64.b64encode(sk.sign(bmessage))
                # print("signature is",signature)
                return signature,public_key_hex

def hash_certificate(public_key_hex): # not verified yet
                hash_cert =hashlib.sha256(public_key_hex.encode('utf-8')).hexdigest()
                # print("hash_cert",hash_cert)
                hash_bytes = hash_cert.encode('utf-8')
                base64_encoded_hash_cert = base64.b64encode(hash_bytes)
                base64_decod_hash_cert= base64_encoded_hash_cert.decode("utf-8")
                return base64_decod_hash_cert

def populate_signed_properties(invoice_xml,base64_decod_hash_cert,signature):
                # root = ET.fromstring(invoice_xml)
                with open("invoice_xml.xml", 'w') as file:
                    xml_content=file.write(invoice_xml)
                tree = ET.parse("invoice_xml.xml")
                root = tree.getroot()
                namespaces = {
                    'ext':'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
                    'sig':'urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2',
                    'sac':'urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2', 
                    'xades': 'http://uri.etsi.org/01903/v1.3.2#',
                    'ds': 'http://www.w3.org/2000/09/xmldsig#',}
                elements_to_insert = [('ext', 'UBLExtensions'),('ext', 'UBLExtension'),('ext', 'ExtensionContent'),('sig', 'UBLDocumentSignatures'),('sac', 'SignatureInformation'),
                    ('ds', 'Signature'),('ds', 'Object'),('xades', 'QualifyingProperties'),('xades', 'SignedProperties'),('xades', 'SignedSignatureProperties'),('xades', 'SigningTime'),
                    ('xades', 'SigningCertificate'),('xades', 'Cert'),('xades', 'IssuerSerial'),('ds', 'X-509IssuerName'),('ds', 'X-509SerialNumber'),('xades', 'CertDigest'),('ds', 'DigestValue')]
                for prefix, uri in namespaces.items():
                    ET.register_namespace(prefix, uri)
                current_element = root
                for ns, tag_name in elements_to_insert:
                    new_element = ET.Element(f"{{{namespaces[ns]}}}{tag_name}")
                    if tag_name == 'DigestValue':
                        new_element.text = base64_decod_hash_cert
                    if tag_name == 'SigningTime':
                        new_element.text =str(datetime.utcnow().isoformat())
                    if tag_name == 'X-509IssuerName':
                        new_element.text = "E=husna@gmail.com, CN=ERP, OU=ERPGULF, O=WE, L=ER, ST=RIYAD, C=SA"
                    if tag_name == 'X-509SerialNumber':
                        new_element.text = "294932932413855994052542058908583632493074097051"
                    current_element.insert(0, new_element)
                    current_element = new_element  
                tree.write("step4xml.xml", encoding='utf-8', xml_declaration=True)
                with open("step4xml.xml", 'r', encoding='utf-8') as file:
                    content = file.read()
# step5  
                tree = ET.parse("step4xml.xml")
                root2= tree.getroot()
                xpath_signedProp = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties")
                signed_prop_tag = root2.find(xpath_signedProp , namespaces)
                # serialize the tag to string without spaces 
                signed_properties_xml = ET.tostring(signed_prop_tag , encoding='utf-8').decode().replace(" ", "")
                # Hash the serialized SignedProperties using SHA-256
                signed_properties_hash = hashlib.sha256(signed_properties_xml.encode()).digest()
                signed_properties_hex = signed_properties_hash.hex()
                signed_properties_base64 = base64.b64encode(bytes.fromhex(signed_properties_hex)).decode()
                print(signed_properties_base64)
                # Encode the hash using HEX-to-Base64 Encoder
                # signed_properties_base64 = base64.b64encode(signed_properties_hash).decode()
#step 6
                updated_invoice_xml = etree.parse("step4xml.xml")
                root3 = updated_invoice_xml.getroot()
                print(root3)
                xpath_signvalue = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:SignatureValue")
                xpath_x509certi = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate")
                xpath_digvalue = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:SignedInfo/ds:Reference[@URI='#xadesSignedProperties']/ds:DigestValue")
                xpath_digvalue2 = ("ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent/sig:UBLDocumentSignatures/sac:SignatureInformation/ds:Signature/ds:SignedInfo/ds:Reference[@Id='invoiceSignedData']/ds:DigestValue")
                signValue6 = root3.find(xpath_signvalue , namespaces)
                x509Certificate6 = root3.find(xpath_x509certi , namespaces)
                digestvalue6 = root3.find(xpath_digvalue , namespaces)
                digestvalue6_2 = root3.find(xpath_digvalue2 , namespaces)
                if signValue6 is not None:
                    signValue6.text = signature
                if x509Certificate6 is not None:
                    x509Certificate6.text = "New Certificate Value"
                if digestvalue6 is not None:
                    digestvalue6.text = "New Digest Value for URI='#xadesSignedProperties'"
                if digestvalue6_2 is not None:
                    digestvalue6_2.text = signed_properties_base64
                tree.write("aftersignxml.xml", encoding='utf-8', xml_declaration=True)
                with open("aftersignxml.xml", 'r', encoding='utf-8') as file:
                    content = file.read()
                    print(content)
                # x509Certificate6.text = (decoded_binary_security_token)
                # digestvalue6.text = (signed_properties_base64)
                # digestvalue6_2.text = (encoded_invoice_hash)
               
def sign_with_Private_key(hash_value):
        try:  
            pri_key="MEQCIGvLa1f3uMCe0AidKUWJ5ghMiDMRcC0qO78ntcTKVOYgAiAKBkX+uuFhbIcye3JznNa45qH1twlLFu/qPzEQ9HMNLw=="
            # pri_key_hex=pri_key.encode('utf-8').hex()
            private_key = ecdsa.SigningKey.from_string(bytes.fromhex(pri_key), curve=ecdsa.SECP256k1)
    # Sign the message
            signature = private_key.sign(hash_value.encode('utf-8'), hashfunc=hashlib.sha256)
            return signature
        except Exception as e:
            print(e)
            sys.exit
            # Sign the message
            # signature = private_key.sign(
            #     hash_value.encode('utf-8'),
            #     ec.ECDSA(hashes.SHA256())
            #     )
            # print("Base64-encoded signature:", signature.hex())
            # return signature


    # Print or use the signature
  
def sign_xml(invoice_xml,hash_value):
                try:
                    with open("rsaprivate_key.pem", 'rb') as key_file:
                        private_key = RSA.import_key(key_file.read())
                    hash_bytes = bytes.fromhex(hash_value)
                    print("hash_bytes is",hash_bytes)
                    signature = pkcs1_15.new(private_key).sign(SHA256.new(hash_bytes))
                    signature_str = b64encode(signature).decode('utf-8')
                    return signature_str
                except Exception as e:
                    print("Error:", e)



def create_File_SignedXML(invoice_xml):
                    sbXml = chilkat2.StringBuilder()
                    sbXml.Append(invoice_xml)
                    success = sbXml.WriteFile("signedXml.xml", "utf-8", False)
                    return sbXml
                
# def zatca_Verification(sbXml):
                    # verifier = chilkat2.XmlDSig()
                    # success = verifier.LoadSignatureSb(sbXml)
                    # if (success != True):
                    #     print(verifier.LastErrorText)
                    #     sys.exit()
                    # verifier.UncommonOptions = "ZATCA"
                    # numSigs = verifier.NumSignatures
                    # verifyIdx = 0
                    # while verifyIdx < numSigs :
                    #     verifier.Selector = verifyIdx
                    #     verified = verifier.VerifySignature(True)
                    #     if (verified != True):
                    #         print(verifier.LastErrorText)
                    #         sys.exit()
                    #     verifyIdx = verifyIdx + 1
                    # print("All signatures were successfully verified.")
                    # tree = ET.parse(sbXml)
                    # root = tree.getroot()
                    # signature_element = root.find(".//Signature")
                    # signature_value = signature_element.find(".//SignatureValue").text
                    # signed_info_element = signature_element.find(".//SignedInfo")
                    # signed_info_canonical = ET.tostring(signed_info_element, method="c14n")
                    # with open("propub.pem", 'rb') as key_file:
                    #     public_key = load_pem_x509_certificate(key_file.read(), default_backend()).public_key()
                    # try:
                    #     public_key.verify(
                    #         bytes.fromhex(signature_value),
                    #         signed_info_canonical,
                    #         padding.PKCS1v15(),
                    #         hashes.SHA256()
                    #     )
                    #     print("Signature verification successful.")
                    # except Exception as e:
                    #     print(f"Signature verification failed: {e}")
                    #     sys.exit()
    
def qrcode_Creation():
                    sellerName = "Firoz Ashraf"
                    vatNumber = "1234567891"
                    timeStamp = "2021-11-17 08:30:00"
                    invoiceTotal = "100.00"
                    vatTotal = "15.00"
                    bdTlv = chilkat2.BinData()
                    charset = "utf-8"
                    tag = 1
                    bdTlv.AppendByte(tag)
                    bdTlv.AppendCountedString(1,False,sellerName,charset)
                    tag = tag + 1
                    bdTlv.AppendByte(tag)
                    bdTlv.AppendCountedString(1,False,vatNumber,charset)
                    tag = tag + 1
                    bdTlv.AppendByte(tag)
                    bdTlv.AppendCountedString(1,False,timeStamp,charset)
                    tag = tag + 1
                    bdTlv.AppendByte(tag)
                    bdTlv.AppendCountedString(1,False,invoiceTotal,charset)
                    tag = tag + 1
                    bdTlv.AppendByte(tag)
                    bdTlv.AppendCountedString(1,False,vatTotal,charset)
                    sbDigestValue, xmlSigned, signedXmlFilePath = get_signed_xml_invoice_for_clearance()
                    tag = 6
                    bdTlv.AppendByte(tag)
                    bdTlv.AppendByte(sbDigestValue.Length)
                    bdTlv.AppendSb(sbDigestValue,"utf-8")
                    sbSignatureValue = chilkat2.StringBuilder()
                    success = xmlSigned.GetChildContentSb("ext:UBLExtensions|ext:UBLExtension|ext:ExtensionContent|sig:UBLDocumentSignatures|sac:SignatureInformation|ds:Signature|ds:SignatureValue",sbSignatureValue)
                    if (success == False):
                        print("Failed to get SignatureValue from signed XML.")
                        sys.exit()
                    qr_base64 = bdTlv.GetEncoded("base64")
                    return bdTlv

def add_QRcode_To_Xml(bdTlv): 
                    #adding qr code to already having signed xml
                    signedXmlFilePath = "/opt/oxy/frappe-bench/sites/signedXml.xml"   
                    xmlQR = chilkat2.Xml()
                    xmlQR.Tag = "cac:AdditionalDocumentReference"
                    xmlQR.UpdateChildContent("cbc:ID","QR")
                    xmlQR.UpdateAttrAt("cac:Attachment|cbc:EmbeddedDocumentBinaryObject",True,"mimeCode","text/plain")
                    sbSignedXml = chilkat2.StringBuilder()
                    success = sbSignedXml.LoadFile(signedXmlFilePath,"utf-8")
                    if (success == False):
                        print("Failed to load previously signed XML file.")
                        sys.exit()
                    sbReplaceStr = chilkat2.StringBuilder()
                    xmlQR.EmitXmlDecl = False
                    xmlQR.EmitCompact = True
                    sample_string = '''GsiuvGjvchjbFhibcDhjv1886G'''
                    success = sbSignedXml.ReplaceFirst(sample_string,bdTlv.GetEncoded("base64"))
                    if success == False:
                        print("Failed to replace <cac:Signature> with QR code in the signed XML.")
                        sys.exit()
                    print(sbSignedXml.GetAsString())
                    if (success == False):
                        print("Did not find <cac:Signature> in the signed XML")
                        sys.exit()
                    success = sbSignedXml.WriteFile("signedXML_withQR.xml","utf-8",False)
                    return sbSignedXml

def verify_SignXML_withQR(sbSignedXml):                 
                        verifier = chilkat2.XmlDSig()
                        success = verifier.LoadSignatureSb(sbSignedXml)
                        if (success != True):
                            print(verifier.LastErrorText)
                            sys.exit()
                        verifier.UncommonOptions = "ZATCA"
                        numSigs = verifier.NumSignatures
                        verifyIdx = 0
                        while verifyIdx < numSigs :
                            verifier.Selector = verifyIdx
                            verified = verifier.VerifySignature(True)
                            if (verified != True):
                                    print(verifier.LastErrorText)
                                    sys.exit()
                            verifyIdx = verifyIdx + 1
                        print("All signatures were successfully verified.")
                   
def signedXml_Withtoken():
                        otp = "123345"
                        signedXmlFilePath = "/opt/oxy/frappe-bench/sites/signedXml.xml"    
                        token,secret = create_security_token_from_csr()
                        pem = chilkat2.Pem()
                        signedXml = chilkat2.Xml()
                        success = signedXml.LoadXmlFile(signedXmlFilePath)
                        if (success == False):
                            print(signedXml.LastErrorText)
                            sys.exit()
                        return signedXml

def get_InvoiceHash(signedXml):
                        invoiceHash = signedXml.GetChildContent("ext:UBLExtensions|ext:UBLExtension|ext:ExtensionContent|sig:UBLDocumentSignatures|sac:SignatureInformation|ds:Signature|ds:SignedInfo|ds:Reference[0]|ds:DigestValue")
                        return invoiceHash

def  get_UUID(signedXml):
                        cbc_UUID = signedXml.GetChildContent("cbc:UUID")
                        uuid  =cbc_UUID
                        return uuid

def get_Clearance_Status(result):
                        try:
                            json_data = json.loads(result.text)
                            clearance_status = json_data.get("clearanceStatus")
                            print("clearance statur: " + clearance_status)
                            return clearance_status
                        except Exception as e:
                            print(e)
                       
def invoice_Zatca_call(invoice_number):
                    # try:
                        invoice_xml,hash_value=get_Actual_Value_And_Rendering(invoice_number)
                        signature,public_key_hex=sign_ECDSA_msg(hash_value)
                        base64_decod_hash_cert=hash_certificate(public_key_hex)
                        modified_xml= populate_signed_properties(invoice_xml,base64_decod_hash_cert,signature )
                        # print(modified_xml)
                        # sign_with_Private_key(hash_value)
                        # canolical_xml(invoice_xml)
                        # gen ,sbXml  =  add_Static_Valueto_Xml(invoice_xml)  
                        # sbXml = load_certificate(gen,sbXml)
                        # siganture=sign_xml(invoice_xml,hash_value)
                        # sbXml=create_File_SignedXML(invoice_xml)
                        # zatca_Verification(sbXml) 
                        # bdTlv = qrcode_Creation()
                    #     sbSignedXml= add_QRcode_To_Xml(bdTlv)
                    #     verify_SignXML_withQR(sbSignedXml)  
                    #     signedXml=signedXml_Withtoken()
                    #     invoiceHash=get_InvoiceHash(signedXml)    
                    #     uuid=get_UUID(signedXml)
                    #     result,clearance_status=send_invoice_for_clearance_normal(uuid,invoiceHash)
                    #     current_time =now()
                    #     if clearance_status == "CLEARED":
                    #         frappe.get_doc({"doctype":"Zatca Success log","title":"Zatca invoice call done successfully","message":"This message by Zatca Compliance ","invoice_number": invoice_number,"time":current_time,"zatca_response":result}).insert()    
                    #     else:
                    #         frappe.log_error(title='Zatca invoice call failed in clearance status',message=frappe.get_traceback())
                    #     return (json.dumps(result)) 
                    # except:       
                    #     frappe.log_error(title='Zatca invoice call failed', message=frappe.get_traceback())
invoice_Zatca_call(invoice_number='ACC-SINV-2023-00022')
# sys.exit()
def before_save(invoice_number):  
                    if invoice_number.posting_time == now():
                        frappe.msgprint(" equal to the current time.")
                    else:
                        frappe.msgprint(" not equal to the current time.")

@frappe.whitelist(allow_guest=True)                
def zatca_Background(invoice_number=None):
                    frappe.msgprint(frappe.session.user)
                    return "something"
                    if invoice_number==None:
                            frappe.msgprint("No invoice number received")
                            return
                
                    # invoice_Zatca_call(invoice_number='ACC-SINV-2023-00022')
#                     frappe.enqueue(
#                             invoice_Zatca_call,
#                             queue="short",
#                             timeout=200,
#                             invoice_number=invoice_number)

                 # frappe.ZATCA_ERROR_EMAILS = {
                                    #          "ADMINS": [
                                    #["Person 1", "husna@htsqatar.com"]
                                    #                    ],
                                    #"SERVER_EMAIL": "19mcs55@meaec.edu.in"
                                    #}
# doc=frappe.get_doc('Sales Invoice','ACC-SINV-2023-00012')
# invoice_Zatca_call(invoice_number='ACC-SINV-2023-00022')