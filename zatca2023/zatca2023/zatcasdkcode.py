import frappe
import os
# frappe.init(site="prod.erpgulf.com")
# frappe.connect()
import xml.etree.ElementTree as ET
import uuid 
import hashlib
import base64
import subprocess
from frappe.utils import now
import re
from lxml import etree
import xml.dom.minidom as minidom
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from datetime import datetime
import xml.etree.ElementTree as ET
import json
import html
import xml.etree.ElementTree as ElementTree
from frappe.utils import execute_in_shell
import sys
import frappe 
import requests
from frappe.utils.data import  get_time

import base64

def clean_up_certificate_string(certificate_string):
    return certificate_string.replace("-----BEGIN CERTIFICATE-----\n", "").replace("-----END CERTIFICATE-----", "").strip()

def get_auth_headers(certificate=None, secret=None):
    if certificate and secret:
        certificate_stripped = clean_up_certificate_string(certificate)
        certificate_base64 = base64.b64encode(certificate_stripped.encode()).decode()
        credentials = f"{certificate_base64}:{secret}"
        basic_token = base64.b64encode(credentials.encode()).decode()
        return basic_token
        
    return {}


def _execute_in_shell(cmd, verbose=False, low_priority=False, check_exit_code=False):
                # using Popen instead of os.system - as recommended by python docs
                import shlex
                import tempfile
                from subprocess import Popen
                env_variables = {"MY_VARIABLE": "some_value", "ANOTHER_VARIABLE": "another_value"}
                if isinstance(cmd, list):
                    # ensure it's properly escaped; only a single string argument executes via shell
                    cmd = shlex.join(cmd)
                    # process = subprocess.Popen(command_sign_invoice, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env_variables)               
                with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                    kwargs = {"shell": True, "stdout": stdout, "stderr": stderr}
                    if low_priority:
                        kwargs["preexec_fn"] = lambda: os.nice(10)
                    p = Popen(cmd, **kwargs)
                    exit_code = p.wait()
                    stdout.seek(0)
                    out = stdout.read()
                    stderr.seek(0)
                    err = stderr.read()
                failed = check_exit_code and exit_code

                if verbose or failed:
                    if err:
                        print(err)
                    if out:
                        print(out)
                if failed:
                    raise Exception("Command failed")
                return err, out

def get_Tax_for_Item(full_string,item):
            try:                                          # getting tax percentage and tax amount
                data = json.loads(full_string)
                tax_percentage=data.get(item,[0,0])[0]
                tax_amount = data.get(item, [0, 0])[1]
                return tax_amount,tax_percentage
            except Exception as e:
                    frappe.throw("error occured in tax for item"+ str(e) )

def get_ICV_code(invoice_number):
                try:
                    icv_code =  re.sub(r'\D', '', invoice_number)   # taking the number part only from doc name
                    return icv_code
                except Exception as e:
                    frappe.throw("error in getting icv number"+ str(e) )
                    
def  get_Issue_Time(invoice_number): 
                doc = frappe.get_doc("Sales Invoice", invoice_number)
                time = get_time(doc.posting_time)
                issue_time = time.strftime("%H:%M:%S")  #time in format of  hour,mints,secnds
                return issue_time

  
def xml_tags():
            try: 
                invoice = ET.Element("Invoice", xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2" )
                invoice.set("xmlns:cac", "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2")
                invoice.set("xmlns:cbc", "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2")
                invoice.set("xmlns:ext", "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2")   
                ubl_extensions = ET.SubElement(invoice, "ext:UBLExtensions")
                ubl_extension = ET.SubElement(ubl_extensions, "ext:UBLExtension")
                extension_uri = ET.SubElement(ubl_extension, "ext:ExtensionURI")
                extension_uri.text = "urn:oasis:names:specification:ubl:dsig:enveloped:xades"
                extension_content = ET.SubElement(ubl_extension, "ext:ExtensionContent")
                UBL_Document_Signatures = ET.SubElement(extension_content , "sig:UBLDocumentSignatures"    )
                UBL_Document_Signatures.set("xmlns:sig" , "urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2")
                UBL_Document_Signatures.set("xmlns:sac" , "urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2")
                UBL_Document_Signatures.set("xmlns:sbc" , "urn:oasis:names:specification:ubl:schema:xsd:SignatureBasicComponents-2")
                Signature_Information = ET.SubElement(UBL_Document_Signatures , "sac:SignatureInformation"  )
                id = ET.SubElement(Signature_Information , "cbc:ID"  )
                id.text = "urn:oasis:names:specification:ubl:signature:1"
                Referenced_SignatureID = ET.SubElement(Signature_Information , "sbc:ReferencedSignatureID"  )
                Referenced_SignatureID.text = "urn:oasis:names:specification:ubl:signature:Invoice"
                Signature = ET.SubElement(Signature_Information , "ds:Signature"  )
                Signature.set("Id" , "signature" )
                Signature.set("xmlns:ds" , "http://www.w3.org/2000/09/xmldsig#" )
                Signed_Info = ET.SubElement(Signature , "ds:SignedInfo"  )
                Canonicalization_Method = ET.SubElement(Signed_Info , "ds:CanonicalizationMethod"  )
                Canonicalization_Method.set("Algorithm" , "http://www.w3.org/2006/12/xml-c14n11"  )
                Signature_Method = ET.SubElement(Signed_Info , "ds:SignatureMethod"  )
                Signature_Method.set("Algorithm" , "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"  )
                Reference = ET.SubElement(Signed_Info , "ds:Reference"  )
                Reference.set("Id"  , "invoiceSignedData")
                Reference.set("URI"  , "")
                Transforms = ET.SubElement(Reference , "ds:Transforms" )
                Transform = ET.SubElement(Transforms , "ds:Transform" )
                Transform.set("Algorithm" , "http://www.w3.org/TR/1999/REC-xpath-19991116")
                XPath = ET.SubElement(Transform , "ds:XPath" )
                XPath.text = "not(//ancestor-or-self::ext:UBLExtensions)"
                Transform2 = ET.SubElement(Transforms , "ds:Transform" )
                Transform2.set("Algorithm" , "http://www.w3.org/TR/1999/REC-xpath-19991116")
                XPath2 = ET.SubElement(Transform2 , "ds:XPath" )
                XPath2.text = "not(//ancestor-or-self::cac:Signature)"
                Transform3 = ET.SubElement(Transforms , "ds:Transform" )
                Transform3.set("Algorithm" , "http://www.w3.org/TR/1999/REC-xpath-19991116")
                XPath3 = ET.SubElement(Transform3 , "ds:XPath" )
                XPath3.text = "not(//ancestor-or-self::cac:AdditionalDocumentReference[cbc:ID='QR'])"
                Transform4 = ET.SubElement(Transforms , "ds:Transform" )
                Transform4.set("Algorithm" , "http://www.w3.org/2006/12/xml-c14n11")
                Diges_Method = ET.SubElement(Reference , "ds:DigestMethod" )
                Diges_Method.set("Algorithm" , "http://www.w3.org/2001/04/xmlenc#sha256")
                Diges_value = ET.SubElement(Reference , "ds:DigestValue" )
                Diges_value.text = "O/vEnAxjLAlw8kQUy8nq/5n8IEZ0YeIyBFvdQA8+iFM="
                Reference2 = ET.SubElement(Signed_Info , "ds:Reference"  )
                Reference2.set("URI" , "#xadesSignedProperties")
                Reference2.set("Type" , "http://www.w3.org/2000/09/xmldsig#SignatureProperties")
                Digest_Method1 = ET.SubElement(Reference2 , "ds:DigestMethod"  )
                Digest_Method1.set("Algorithm" , "http://www.w3.org/2001/04/xmlenc#sha256")
                Digest_value1 = ET.SubElement(Reference2 , "ds:DigestValue"  )
                Digest_value1.text="YjQwZmEyMjM2NDU1YjQwNjM5MTFmYmVkODc4NjM2NTc0N2E3OGFmZjVlMzA1ODAwYWE5Y2ZmYmFjZjRiNjQxNg=="
                Signature_Value = ET.SubElement(Signature , "ds:SignatureValue"  )
                Signature_Value.text = "MEQCIDGBRHiPo6yhXIQ9df6pMEkufcGnoqYaS+O8Jn0xagBiAiBtoxpbrwfEJHhUGQHTqzD1ORX5+Z/tumM0wLfZ4cuYRg=="
                KeyInfo = ET.SubElement(Signature , "ds:KeyInfo"  )
                X509Data = ET.SubElement(KeyInfo , "ds:X509Data"  )
                X509Certificate = ET.SubElement(X509Data , "ds:X509Certificate"  )
                X509Certificate.text = "MIID6TCCA5CgAwIBAgITbwAAf8tem6jngr16DwABAAB/yzAKBggqhkjOPQQDAjBjMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxEzARBgoJkiaJk/IsZAEZFgNnb3YxFzAVBgoJkiaJk/IsZAEZFgdleHRnYXp0MRwwGgYDVQQDExNUU1pFSU5WT0lDRS1TdWJDQS0xMB4XDTIyMDkxNDEzMjYwNFoXDTI0MDkxMzEzMjYwNFowTjELMAkGA1UEBhMCU0ExEzARBgNVBAoTCjMxMTExMTExMTExDDAKBgNVBAsTA1RTVDEcMBoGA1UEAxMTVFNULTMxMTExMTExMTEwMTExMzBWMBAGByqGSM49AgEGBSuBBAAKA0IABGGDDKDmhWAITDv7LXqLX2cmr6+qddUkpcLCvWs5rC2O29W/hS4ajAK4Qdnahym6MaijX75Cg3j4aao7ouYXJ9GjggI5MIICNTCBmgYDVR0RBIGSMIGPpIGMMIGJMTswOQYDVQQEDDIxLVRTVHwyLVRTVHwzLWE4NjZiMTQyLWFjOWMtNDI0MS1iZjhlLTdmNzg3YTI2MmNlMjEfMB0GCgmSJomT8ixkAQEMDzMxMTExMTExMTEwMTExMzENMAsGA1UEDAwEMTEwMDEMMAoGA1UEGgwDVFNUMQwwCgYDVQQPDANUU1QwHQYDVR0OBBYEFDuWYlOzWpFN3no1WtyNktQdrA8JMB8GA1UdIwQYMBaAFHZgjPsGoKxnVzWdz5qspyuZNbUvME4GA1UdHwRHMEUwQ6BBoD+GPWh0dHA6Ly90c3RjcmwuemF0Y2EuZ292LnNhL0NlcnRFbnJvbGwvVFNaRUlOVk9JQ0UtU3ViQ0EtMS5jcmwwga0GCCsGAQUFBwEBBIGgMIGdMG4GCCsGAQUFBzABhmJodHRwOi8vdHN0Y3JsLnphdGNhLmdvdi5zYS9DZXJ0RW5yb2xsL1RTWkVpbnZvaWNlU0NBMS5leHRnYXp0Lmdvdi5sb2NhbF9UU1pFSU5WT0lDRS1TdWJDQS0xKDEpLmNydDArBggrBgEFBQcwAYYfaHR0cDovL3RzdGNybC56YXRjYS5nb3Yuc2Evb2NzcDAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMDMCcGCSsGAQQBgjcVCgQaMBgwCgYIKwYBBQUHAwIwCgYIKwYBBQUHAwMwCgYIKoZIzj0EAwIDRwAwRAIgOgjNPJW017lsIijmVQVkP7GzFO2KQKd9GHaukLgIWFsCIFJF9uwKhTMxDjWbN+1awsnFI7RLBRxA/6hZ+F1wtaqU"
                Object = ET.SubElement(Signature , "ds:Object"  )
                QualifyingProperties = ET.SubElement(Object , "xades:QualifyingProperties"  )
                QualifyingProperties.set("Target" , "signature")
                QualifyingProperties.set("xmlns:xades" , "http://uri.etsi.org/01903/v1.3.2#")
                SignedProperties = ET.SubElement(QualifyingProperties , "xades:SignedProperties"  )
                SignedProperties.set("Id" , "xadesSignedProperties")
                SignedSignatureProperties = ET.SubElement(SignedProperties , "xades:SignedSignatureProperties"  )
                SigningTime = ET.SubElement(SignedSignatureProperties , "xades:SigningTime"  )
                SigningTime.text = "2023-01-24T11:36:34Z"
                SigningCertificate = ET.SubElement(SignedSignatureProperties , "xades:SigningCertificate"  )
                Cert = ET.SubElement(SigningCertificate , "xades:Cert"  )
                CertDigest = ET.SubElement(Cert , "xades:CertDigest"  )
                Digest_Method2 = ET.SubElement(CertDigest , "ds:DigestMethod"  )
                Digest_Value2 = ET.SubElement(CertDigest , "ds:DigestValue"  )
                Digest_Method2.set("Algorithm" , "http://www.w3.org/2001/04/xmlenc#sha256")
                Digest_Value2.text = "YTJkM2JhYTcwZTBhZTAxOGYwODMyNzY3NTdkZDM3YzhjY2IxOTIyZDZhM2RlZGJiMGY0NDUzZWJhYWI4MDhmYg=="
                IssuerSerial = ET.SubElement(Cert , "xades:IssuerSerial"  )
                X509IssuerName = ET.SubElement(IssuerSerial , "ds:X509IssuerName"  )
                X509SerialNumber = ET.SubElement(IssuerSerial , "ds:X509SerialNumber"  )
                X509IssuerName.text = "CN=TSZEINVOICE-SubCA-1, DC=extgazt, DC=gov, DC=local"
                X509SerialNumber.text = "2475382886904809774818644480820936050208702411"
                return invoice
            except Exception as e:
                    frappe.throw("error in xml tags formation"+ str(e) )

def salesinvoice_data(invoice,invoice_number):
            try:
                sales_invoice_doc = frappe.get_doc('Sales Invoice' ,invoice_number)
                cbc_ProfileID = ET.SubElement(invoice, "cbc:ProfileID")
                cbc_ProfileID.text = "reporting:1.0"
                cbc_ID = ET.SubElement(invoice, "cbc:ID")
                cbc_ID.text = str(sales_invoice_doc.name)
                cbc_UUID = ET.SubElement(invoice, "cbc:UUID")
                cbc_UUID.text =  str(uuid.uuid1())
                uuid1= cbc_UUID.text
                cbc_IssueDate = ET.SubElement(invoice, "cbc:IssueDate")
                cbc_IssueDate.text = str(sales_invoice_doc.posting_date)
                cbc_IssueTime = ET.SubElement(invoice, "cbc:IssueTime")
                cbc_IssueTime.text = get_Issue_Time(invoice_number)
                return invoice ,uuid1 ,sales_invoice_doc
            except Exception as e:
                    frappe.throw("error occured in salesinvoice data"+ str(e) )

def invoice_Typecode_Simplified(invoice,sales_invoice_doc):
            try:                             
                cbc_InvoiceTypeCode = ET.SubElement(invoice, "cbc:InvoiceTypeCode")
                if sales_invoice_doc.is_return == 0:         
                    cbc_InvoiceTypeCode.set("name", "0200000")
                    cbc_InvoiceTypeCode.text = "388"
                elif sales_invoice_doc.is_return == 1:       # return items and simplified invoice
                    cbc_InvoiceTypeCode.set("name", "0211000")
                    cbc_InvoiceTypeCode.text = "381"
                return invoice
            except Exception as e:
                    frappe.throw("error occured in simplified invoice typecode"+ str(e) )

def invoice_Typecode_Standard(invoice,sales_invoice_doc):
            try:
                    cbc_InvoiceTypeCode = ET.SubElement(invoice, "cbc:InvoiceTypeCode")
                    cbc_InvoiceTypeCode.set("name", "0100000") 
                    if sales_invoice_doc.is_return == 0:
                        cbc_InvoiceTypeCode.text = "388"
                    elif sales_invoice_doc.is_return == 1:     # return items and simplified invoice
                        cbc_InvoiceTypeCode.text = "381"
                    return invoice
            except Exception as e:
                    frappe.throw("Error in standard invoice type code"+ str(e))
                    
def doc_Reference(invoice,sales_invoice_doc,invoice_number):
            try:
                cbc_DocumentCurrencyCode = ET.SubElement(invoice, "cbc:DocumentCurrencyCode")
                cbc_DocumentCurrencyCode.text = sales_invoice_doc.currency
                cbc_TaxCurrencyCode = ET.SubElement(invoice, "cbc:TaxCurrencyCode")
                cbc_TaxCurrencyCode.text = sales_invoice_doc.currency
                if sales_invoice_doc.is_return == 1:
                                invoice=billing_reference_for_credit_and_debit_note(invoice,sales_invoice_doc)
                cac_AdditionalDocumentReference = ET.SubElement(invoice, "cac:AdditionalDocumentReference")
                cbc_ID_1 = ET.SubElement(cac_AdditionalDocumentReference, "cbc:ID")
                # cbc_ID_1.text = sales_invoice_doc.custom_document_id
                cbc_ID_1.text = "ICV"
                cbc_UUID_1 = ET.SubElement(cac_AdditionalDocumentReference, "cbc:UUID")
                cbc_UUID_1.text = str(get_ICV_code(invoice_number))
                return invoice  
            except Exception as e:
                    frappe.throw("Error occured in  reference doc" + str(e) )

def additional_Reference(invoice):
            try:
                # settings=frappe.get_doc('Zatca setting')
                cac_AdditionalDocumentReference2 = ET.SubElement(invoice, "cac:AdditionalDocumentReference")
                cbc_ID_1_1 = ET.SubElement(cac_AdditionalDocumentReference2, "cbc:ID")
                cbc_ID_1_1.text = "PIH"
                cac_Attachment = ET.SubElement(cac_AdditionalDocumentReference2, "cac:Attachment")
                cbc_EmbeddedDocumentBinaryObject = ET.SubElement(cac_Attachment, "cbc:EmbeddedDocumentBinaryObject")
                cbc_EmbeddedDocumentBinaryObject.set("mimeCode", "text/plain")
                # cbc_EmbeddedDocumentBinaryObject.text = settings.pih
                cbc_EmbeddedDocumentBinaryObject.text = "L0Awl814W4ycuFvjDVL/vIW08mNRNAwqfdlF5i/3dpU="
            # QR CODE ------------------------------------------------------------------------------------------------------------------------------------------------------------------
                cac_AdditionalDocumentReference22 = ET.SubElement(invoice, "cac:AdditionalDocumentReference")
                cbc_ID_1_12 = ET.SubElement(cac_AdditionalDocumentReference22, "cbc:ID")
                cbc_ID_1_12.text = "QR"
                cac_Attachment22 = ET.SubElement(cac_AdditionalDocumentReference22, "cac:Attachment")
                cbc_EmbeddedDocumentBinaryObject22 = ET.SubElement(cac_Attachment22, "cbc:EmbeddedDocumentBinaryObject")
                cbc_EmbeddedDocumentBinaryObject22.set("mimeCode", "text/plain")
                cbc_EmbeddedDocumentBinaryObject22.text = "GsiuvGjvchjbFhibcDhjv1886G"
            #END  QR CODE ------------------------------------------------------------------------------------------------------------------------------------------------------------------
                cac_sign = ET.SubElement(invoice, "cac:Signature")
                cbc_id_sign = ET.SubElement(cac_sign, "cbc:ID")
                cbc_method_sign = ET.SubElement(cac_sign, "cbc:SignatureMethod")
                cbc_id_sign.text = "urn:oasis:names:specification:ubl:signature:Invoice"
                cbc_method_sign.text = "urn:oasis:names:specification:ubl:dsig:enveloped:xades"
                return invoice
            except Exception as e:
                    frappe.throw("error occured in additional refrences" + str(e) )

def company_Data(invoice,sales_invoice_doc):
            try:
                company_doc = frappe.get_doc("Company", sales_invoice_doc.company)
                cac_AccountingSupplierParty = ET.SubElement(invoice, "cac:AccountingSupplierParty")
                cac_Party_1 = ET.SubElement(cac_AccountingSupplierParty, "cac:Party")
                cac_PartyIdentification = ET.SubElement(cac_Party_1, "cac:PartyIdentification")
                cbc_ID_2 = ET.SubElement(cac_PartyIdentification, "cbc:ID")
                cbc_ID_2.set("schemeID", "CRN")
                try:
                    cbc_ID_2.text =company_doc.custom_accounting_supplier_party_id
                # cbc_ID_2.text ="1234567890"
                except Exception as e:
                    frappe.throw("error occured in company supplier id "+ str(e) )
                cac_PostalAddress = ET.SubElement(cac_Party_1, "cac:PostalAddress")
                cbc_StreetName = ET.SubElement(cac_PostalAddress, "cbc:StreetName")
                # cbc_StreetName.text = company_doc.custom_street
                cbc_StreetName.text = "comp street"
                cbc_BuildingNumber = ET.SubElement(cac_PostalAddress, "cbc:BuildingNumber")
                # cbc_BuildingNumber.text = str(company_doc.custom_build_no)
                cbc_BuildingNumber.text = "1235"
                cbc_PlotIdentification = ET.SubElement(cac_PostalAddress, "cbc:PlotIdentification")
                # cbc_PlotIdentification.text =  company_doc.custom_plot_id_no
                cbc_PlotIdentification.text =  "4562"
                cbc_CitySubdivisionName = ET.SubElement(cac_PostalAddress, "cbc:CitySubdivisionName")
                # cbc_CitySubdivisionName.text = company_doc.custom_sub
                cbc_CitySubdivisionName.text = "my sub"
                cbc_CityName = ET.SubElement(cac_PostalAddress, "cbc:CityName")
                # cbc_CityName.text = company_doc.custom_city
                cbc_CityName.text = "my city"
                cbc_PostalZone = ET.SubElement(cac_PostalAddress, "cbc:PostalZone")
                # cbc_PostalZone.text = str(company_doc.custom_pincode)
                cbc_PostalZone.text = "12345"
                cbc_CountrySubentity = ET.SubElement(cac_PostalAddress, "cbc:CountrySubentity")
                # cbc_CountrySubentity.text = company_doc.custom_state
                cbc_CountrySubentity.text = "my state"
                cac_Country = ET.SubElement(cac_PostalAddress, "cac:Country")
                cbc_IdentificationCode = ET.SubElement(cac_Country, "cbc:IdentificationCode")
                # cbc_IdentificationCode.text = company_doc.custom_country_name
                cbc_IdentificationCode.text = "SA"
                cac_PartyTaxScheme = ET.SubElement(cac_Party_1, "cac:PartyTaxScheme")
                cbc_CompanyID = ET.SubElement(cac_PartyTaxScheme, "cbc:CompanyID")
                # cbc_CompanyID.text = "310122393500003"    # Here seller tax id is given
                cbc_CompanyID.text = company_doc.tax_id
                cac_TaxScheme = ET.SubElement(cac_PartyTaxScheme, "cac:TaxScheme")
                cbc_ID_3 = ET.SubElement(cac_TaxScheme, "cbc:ID")
                cbc_ID_3.text = "VAT"
                cac_PartyLegalEntity = ET.SubElement(cac_Party_1, "cac:PartyLegalEntity")
                cbc_RegistrationName = ET.SubElement(cac_PartyLegalEntity, "cbc:RegistrationName")
                cbc_RegistrationName.text = sales_invoice_doc.company
                # cbc_RegistrationName.text = "ABCD Limited"
                return invoice
            except Exception as e:
                    frappe.throw("error occured in company data"+ str(e) )

def customer_Data(invoice,sales_invoice_doc):
            try:
                customer_doc= frappe.get_doc("Customer",sales_invoice_doc.customer)
                cac_AccountingCustomerParty = ET.SubElement(invoice, "cac:AccountingCustomerParty")
                cac_Party_2 = ET.SubElement(cac_AccountingCustomerParty, "cac:Party")
                cac_PartyIdentification_1 = ET.SubElement(cac_Party_2, "cac:PartyIdentification")
                cbc_ID_4 = ET.SubElement(cac_PartyIdentification_1, "cbc:ID")
                cbc_ID_4.set("schemeID", "SAG")
                # cbc_ID_4.text = customer_doc.custom_accounting_customer_id
                cbc_ID_4.text ="543261789"
                if int(frappe.__version__.split('.')[0]) == 15:
                    address = frappe.get_doc("Address", customer_doc.customer_primary_address)    
                else:
                    address = frappe.get_doc("Address", customer_doc.customer_address)
                cac_PostalAddress_1 = ET.SubElement(cac_Party_2, "cac:PostalAddress")
                cbc_StreetName_1 = ET.SubElement(cac_PostalAddress_1, "cbc:StreetName")
                cbc_StreetName_1.text = address.address_line1
                cbc_BuildingNumber_1 = ET.SubElement(cac_PostalAddress_1, "cbc:BuildingNumber")
                cbc_BuildingNumber_1.text = address.address_line2
                cbc_PlotIdentification_1 = ET.SubElement(cac_PostalAddress_1, "cbc:PlotIdentification")
                if hasattr(address, 'po_box'):
                    cbc_PlotIdentification_1.text = address.po_box
                else:
                    cbc_PlotIdentification_1.text = address.address_line1
                cbc_CitySubdivisionName_1 = ET.SubElement(cac_PostalAddress_1, "cbc:CitySubdivisionName")
                cbc_CitySubdivisionName_1.text = address.address_line2
                cbc_CityName_1 = ET.SubElement(cac_PostalAddress_1, "cbc:CityName")
                cbc_CityName_1.text = address.city
                cbc_PostalZone_1 = ET.SubElement(cac_PostalAddress_1, "cbc:PostalZone")
                cbc_PostalZone_1.text =address.pincode
                cbc_CountrySubentity_1 = ET.SubElement(cac_PostalAddress_1, "cbc:CountrySubentity")
                cbc_CountrySubentity_1.text =address.state
                cac_Country_1 = ET.SubElement(cac_PostalAddress_1, "cac:Country")
                cbc_IdentificationCode_1 = ET.SubElement(cac_Country_1, "cbc:IdentificationCode")
                cbc_IdentificationCode_1.text = "SA" 
                cac_PartyTaxScheme_1 = ET.SubElement(cac_Party_2, "cac:PartyTaxScheme")
                cac_TaxScheme_1 = ET.SubElement(cac_PartyTaxScheme_1, "cac:TaxScheme")
                cbc_ID_5 = ET.SubElement(cac_TaxScheme_1, "cbc:ID")
                cbc_ID_5.text = "VAT"
                cac_PartyLegalEntity_1 = ET.SubElement(cac_Party_2, "cac:PartyLegalEntity")
                cbc_RegistrationName_1 = ET.SubElement(cac_PartyLegalEntity_1, "cbc:RegistrationName")
                cbc_RegistrationName_1.text = sales_invoice_doc.customer
                return invoice
            except Exception as e:
                    frappe.throw("error occured in customer data"+ str(e) )

def delivery_And_PaymentMeans(invoice,sales_invoice_doc, is_return):
            try:
                cac_Delivery = ET.SubElement(invoice, "cac:Delivery")
                cbc_ActualDeliveryDate = ET.SubElement(cac_Delivery, "cbc:ActualDeliveryDate")
                cbc_ActualDeliveryDate.text = str(sales_invoice_doc.due_date)
                cac_PaymentMeans = ET.SubElement(invoice, "cac:PaymentMeans")
                cbc_PaymentMeansCode = ET.SubElement(cac_PaymentMeans, "cbc:PaymentMeansCode")
                # cbc_PaymentMeansCode.text = str(sales_invoice_doc.custom_payment_code)
                cbc_PaymentMeansCode.text = "32"
                
                if is_return == 1:
                    cbc_InstructionNote = ET.SubElement(cac_PaymentMeans, "cbc:InstructionNote")
                    cbc_InstructionNote.text = "Cancellation"    
                return invoice
            except Exception as e:
                    frappe.throw("Delivery and payment means failed"+ str(e) )
                    
def billing_reference_for_credit_and_debit_note(invoice,sales_invoice_doc):
            frappe.msgprint("credit and debit note")
            try:
                #details of original invoice
                cac_BillingReference = ET.SubElement(invoice, "cac:BillingReference")
                cac_InvoiceDocumentReference = ET.SubElement(cac_BillingReference, "cac:InvoiceDocumentReference")
                cbc_ID13 = ET.SubElement(cac_InvoiceDocumentReference, "cbc:ID")
                cbc_ID13.text = sales_invoice_doc.return_against  # field from return against invoice. 
                
                return invoice
            except Exception as e:
                    frappe.throw("credit and debit note billing failed"+ str(e) )


def tax_Data(invoice,sales_invoice_doc):
            try:
                cac_TaxTotal = ET.SubElement(invoice, "cac:TaxTotal")
                cbc_TaxAmount = ET.SubElement(cac_TaxTotal, "cbc:TaxAmount")
                cbc_TaxAmount.set("currencyID", sales_invoice_doc.currency) # SAR is given earlier directly
                cbc_TaxAmount.text =str( abs(sales_invoice_doc.base_total_taxes_and_charges))
                cac_TaxSubtotal = ET.SubElement(cac_TaxTotal, "cac:TaxSubtotal")
                cbc_TaxableAmount = ET.SubElement(cac_TaxSubtotal, "cbc:TaxableAmount")
                cbc_TaxableAmount.set("currencyID", sales_invoice_doc.currency)
                cbc_TaxableAmount.text =str(abs(sales_invoice_doc.base_net_total))
                cbc_TaxAmount_2 = ET.SubElement(cac_TaxSubtotal, "cbc:TaxAmount")
                cbc_TaxAmount_2.set("currencyID", sales_invoice_doc.currency)
                cbc_TaxAmount_2.text =  str(abs(sales_invoice_doc.base_total_taxes_and_charges))
                cac_TaxCategory_1 = ET.SubElement(cac_TaxSubtotal, "cac:TaxCategory")
                cbc_ID_8 = ET.SubElement(cac_TaxCategory_1, "cbc:ID")
                cbc_ID_8.text =  "S"
                cbc_Percent_1 = ET.SubElement(cac_TaxCategory_1, "cbc:Percent")
                # cbc_Percent_1.text = str(sales_invoice_doc.taxes[0].rate)
                cbc_Percent_1.text = f"{float(sales_invoice_doc.taxes[0].rate):.2f}"                
                cac_TaxScheme_3 = ET.SubElement(cac_TaxCategory_1, "cac:TaxScheme")
                cbc_ID_9 = ET.SubElement(cac_TaxScheme_3, "cbc:ID")
                cbc_ID_9.text = "VAT"
                cac_TaxTotal = ET.SubElement(invoice, "cac:TaxTotal")
                cbc_TaxAmount = ET.SubElement(cac_TaxTotal, "cbc:TaxAmount")
                cbc_TaxAmount.set("currencyID", sales_invoice_doc.currency)
                cbc_TaxAmount.text =str( abs(sales_invoice_doc.base_total_taxes_and_charges))
                cac_LegalMonetaryTotal = ET.SubElement(invoice, "cac:LegalMonetaryTotal")
                cbc_LineExtensionAmount = ET.SubElement(cac_LegalMonetaryTotal, "cbc:LineExtensionAmount")
                cbc_LineExtensionAmount.set("currencyID", sales_invoice_doc.currency)
                cbc_LineExtensionAmount.text =  str(abs(sales_invoice_doc.base_net_total))
                cbc_TaxExclusiveAmount = ET.SubElement(cac_LegalMonetaryTotal, "cbc:TaxExclusiveAmount")
                cbc_TaxExclusiveAmount.set("currencyID", sales_invoice_doc.currency)
                cbc_TaxExclusiveAmount.text = str(abs(sales_invoice_doc.base_net_total))
                cbc_TaxInclusiveAmount = ET.SubElement(cac_LegalMonetaryTotal, "cbc:TaxInclusiveAmount")
                cbc_TaxInclusiveAmount.set("currencyID", sales_invoice_doc.currency)
                cbc_TaxInclusiveAmount.text = str(abs(sales_invoice_doc.grand_total))
                cbc_AllowanceTotalAmount = ET.SubElement(cac_LegalMonetaryTotal, "cbc:AllowanceTotalAmount")
                cbc_AllowanceTotalAmount.set("currencyID", sales_invoice_doc.currency)
                cbc_AllowanceTotalAmount.text = str(sales_invoice_doc.base_change_amount)
                cbc_PayableAmount = ET.SubElement(cac_LegalMonetaryTotal, "cbc:PayableAmount")
                cbc_PayableAmount.set("currencyID", sales_invoice_doc.currency)
                cbc_PayableAmount.text = str(abs(sales_invoice_doc.grand_total)) 
                return invoice
             
            except Exception as e:
                    frappe.throw("error occured in tax data"+ str(e) )

def item_data(invoice,sales_invoice_doc):
            try:
                for single_item in sales_invoice_doc.items : 
                    item_tax_amount,item_tax_percentage =  get_Tax_for_Item(sales_invoice_doc.taxes[0].item_wise_tax_detail,single_item.item_code)
                    cac_InvoiceLine = ET.SubElement(invoice, "cac:InvoiceLine")
                    cbc_ID_10 = ET.SubElement(cac_InvoiceLine, "cbc:ID")
                    cbc_ID_10.text = str(single_item.idx)
                    cbc_InvoicedQuantity = ET.SubElement(cac_InvoiceLine, "cbc:InvoicedQuantity")
                    cbc_InvoicedQuantity.set("unitCode", str(single_item.uom))
                    cbc_InvoicedQuantity.text = str(abs(single_item.qty))
                    cbc_LineExtensionAmount_1 = ET.SubElement(cac_InvoiceLine, "cbc:LineExtensionAmount")
                    cbc_LineExtensionAmount_1.set("currencyID", sales_invoice_doc.currency)
                    cbc_LineExtensionAmount_1.text=  str(abs(single_item.amount))
                    cac_TaxTotal_2 = ET.SubElement(cac_InvoiceLine, "cac:TaxTotal")
                    cbc_TaxAmount_3 = ET.SubElement(cac_TaxTotal_2, "cbc:TaxAmount")
                    cbc_TaxAmount_3.set("currencyID", sales_invoice_doc.currency)
                    cbc_TaxAmount_3.text = str(abs(item_tax_amount))
                    cbc_RoundingAmount = ET.SubElement(cac_TaxTotal_2, "cbc:RoundingAmount")
                    cbc_RoundingAmount.set("currencyID", sales_invoice_doc.currency)
                    cbc_RoundingAmount.text=str(abs(single_item.amount) + abs(item_tax_amount) )
                    cac_Item = ET.SubElement(cac_InvoiceLine, "cac:Item")
                    cbc_Name = ET.SubElement(cac_Item, "cbc:Name")
                    cbc_Name.text = single_item.item_code
                    cac_ClassifiedTaxCategory = ET.SubElement(cac_Item, "cac:ClassifiedTaxCategory")
                    cbc_ID_11 = ET.SubElement(cac_ClassifiedTaxCategory, "cbc:ID")
                    # cbc_ID_11.text = sales_invoice_doc.custom_item_character
                    cbc_ID_11.text = "S"
                    cbc_Percent_2 = ET.SubElement(cac_ClassifiedTaxCategory, "cbc:Percent")
                    # cbc_Percent_2.text =str(item_tax_percentage)
                    cbc_Percent_2.text = f"{float(item_tax_percentage):.2f}"
                    # frappe.throw(cbc_Percent_2.text)
                    cac_TaxScheme_4 = ET.SubElement(cac_ClassifiedTaxCategory, "cac:TaxScheme")
                    cbc_ID_12 = ET.SubElement(cac_TaxScheme_4, "cbc:ID")
                    cbc_ID_12.text = "VAT"
                    cac_Price = ET.SubElement(cac_InvoiceLine, "cac:Price")
                    cbc_PriceAmount = ET.SubElement(cac_Price, "cbc:PriceAmount")
                    cbc_PriceAmount.set("currencyID", sales_invoice_doc.currency)
                    cbc_PriceAmount.text =  str(single_item.price_list_rate)
                return invoice
            except Exception as e:
                    frappe.throw("error occured in item data"+ str(e) )

def xml_structuring(invoice,sales_invoice_doc):
            try:
                xml_declaration = "<?xml version='1.0' encoding='UTF-8'?>\n"
                tree = ET.ElementTree(invoice)
                with open(f"xml_files.xml", 'wb') as file:
                    tree.write(file, encoding='utf-8', xml_declaration=True)
                with open(f"xml_files.xml", 'r') as file:
                    xml_string = file.read()
                xml_dom = minidom.parseString(xml_string)
                pretty_xml_string = xml_dom.toprettyxml(indent="  ")   # created xml into formatted xml form 
                with open(f"finalzatcaxml.xml", 'w') as file:
                    file.write(pretty_xml_string)
                          # Attach the getting xml for each invoice
                frappe.msgprint(frappe.session.user)
                try:
                    if frappe.db.exists("File",{ "attached_to_name": sales_invoice_doc.name, "attached_to_doctype": sales_invoice_doc.doctype }):
                        frappe.db.delete("File",{ "attached_to_name":sales_invoice_doc.name, "attached_to_doctype": sales_invoice_doc.doctype })
                except Exception as e:
                    frappe.throw(frappe.get_traceback())
                
                try:
                    fileX = frappe.get_doc(
                        {   "doctype": "File",        
                            "file_type": "xml",  
                            "file_name":  "E-invoice-" + sales_invoice_doc.name + ".xml",
                            "attached_to_doctype":sales_invoice_doc.doctype,
                            "attached_to_name":sales_invoice_doc.name, 
                            "content": pretty_xml_string,
                            "is_private": 1,})
                    fileX.save()
                except Exception as e:
                    frappe.throw(frappe.get_traceback())
                
                try:
                    frappe.msgprint(frappe.db.get_value('File', {'attached_to_name':sales_invoice_doc.name, 'attached_to_doctype': sales_invoice_doc.doctype}, ['file_name']))
                except Exception as e:
                    frappe.throw(frappe.get_traceback())
            except Exception as e:
                    frappe.throw("error occured in xml structuring and attach"+ str(e) )

def get_latest_generated_csr_file(folder_path='.'):
            try:
                files = [f for f in os.listdir(folder_path) if f.startswith("generated-csr") and os.path.isfile(os.path.join(folder_path, f))]
                if not files:
                    return None
                latest_file = max(files, key=os.path.getmtime)
                print(latest_file)
                return os.path.join(folder_path, latest_file)
            except Exception as e:
                    frappe.throw(" error in get_latest_generated_csr_file"+ str(e) )


@frappe.whitelist(allow_guest=True)
def generate_csr():
            try:
                settings=frappe.get_doc('Zatca setting')
                csr_config_file = 'sdkcsrconfig.properties'
                private_key_file = 'sdkprivatekey.pem'
                generated_csr_file = 'sdkcsr.pem'
                SDK_ROOT=settings.sdk_root
                path_string=f"export SDK_ROOT={SDK_ROOT} && export FATOORA_HOME=$SDK_ROOT/Apps && export SDK_CONFIG=$SDK_ROOT/Configuration/config.json && export PATH=$PATH:$FATOORA_HOME &&  "
                
                if settings.select == "Simulation":
                    command_generate_csr =  path_string  + f'fatoora -sim -csr -csrConfig {csr_config_file} -privateKey {private_key_file} -generatedCsr {generated_csr_file} -pem'
                else:
                    command_generate_csr =  path_string  + f'fatoora -csr -csrConfig {csr_config_file} -privateKey {private_key_file} -generatedCsr {generated_csr_file} -pem'
                
                try:
                    err,out = _execute_in_shell(command_generate_csr)
                    frappe.msgprint(out)
                    with open(get_latest_generated_csr_file(), "r") as file_csr:
                        get_csr = file_csr.read()
                    file = frappe.get_doc({
                            "doctype": "File",
                            "file_name": f"generated-csr-{settings.name}.csr",
                            "attached_to_doctype": settings.doctype,
                            "attached_to_name": settings.name,
                            "content": get_csr, })
                    file.save()
                    frappe.msgprint("CSR generation successful. CSR saved")
                except Exception as e:
                    frappe.throw(err)
                    frappe.throw("An error occurred: " + str(e))
            except Exception as e:
                    frappe.throw("error occured in generate csr"+ str(e) )


def get_API_url(base_url):
                try:
                    settings = frappe.get_doc('Zatca setting')
                    if settings.select == "Sandbox":
                        url = settings.sandbox_url + base_url
                    elif settings.select == "Simulation":
                        url = settings.simulation_url + base_url
                    else:
                        url = settings.production_url + base_url
                    return url 
                except Exception as e:
                    frappe.throw(" getting url failed"+ str(e) ) 

@frappe.whitelist(allow_guest=True)
def create_CSID(): 
                try:
                    settings=frappe.get_doc('Zatca setting')     
                    with open(get_latest_generated_csr_file(), "r") as f:
                        csr_contents = f.read()
                    payload = json.dumps({
                    "csr": csr_contents
                    })
                    headers = {
                    'accept': 'application/json',
                    'OTP': settings.otp,
                    'Accept-Version': 'V2',
                    'Content-Type': 'application/json',
                    'Cookie': 'TS0106293e=0132a679c07382ce7821148af16b99da546c13ce1dcddbef0e19802eb470e539a4d39d5ef63d5c8280b48c529f321e8b0173890e4f'
                    }
                    response = requests.request("POST", url=get_API_url(base_url="compliance"), headers=headers, data=payload)
                    frappe.msgprint(str(response.content))
                    # frappe.msgprint(response.status_code)
                    # frappe.msgprint(response.text)
                    frappe.msgprint("the CSID formed through url")
                    data=json.loads(response.text)
                    # compliance_cert =get_auth_headers(data["binarySecurityToken"],data["secret"])
                    concatenated_value = data["binarySecurityToken"] + ":" + data["secret"]
                    encoded_value = base64.b64encode(concatenated_value.encode()).decode()
                    settings.set("basic_auth", encoded_value)
                    settings.save()
                    settings.set("compliance_request_id",data["requestID"])
                    settings.save()
                except Exception as e:
                            frappe.throw("error in csid formation" + str(e))

def create_compliance_x509():
                try:
                    binarySecurityToken = "TUlJQ1JUQ0NBZXlnQXdJQkFnSUdBWXlhUHkvMk1Bb0dDQ3FHU000OUJBTUNNQlV4RXpBUkJnTlZCQU1NQ21WSmJuWnZhV05wYm1jd0hoY05Nak14TWpJME1EVXhORE0yV2hjTk1qZ3hNakl6TWpFd01EQXdXakI1TVFzd0NRWURWUVFHRXdKVFFURVlNQllHQTFVRUN3d1BNekF3T1Rjd09EQTJNVEF3TURBek1TZ3dKZ1lEVlFRS0RCOUJlR2x6SUVsdWMzQmxZM1JwYjI0Z1EyOXVkSEpoWTNScGJtY2dTbE5ETVNZd0pBWURWUVFEREIxVVUxUXRPRGcyTkRNeE1UUTFMVE13TURrM01EZ3dOakV3TURBd016QldNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQUtBMElBQkFMM0R4d1VrRjAzdWxGVnJJM3I5QzI2Qmo2Z09iWXJuNnp0a2IrTHltREVzdjJ5bHBXamowQUdBS2xBNnk4ME9ldWJSQUcxa2dNMlhRQ3VIL1QyK1kramdjWXdnY013REFZRFZSMFRBUUgvQkFJd0FEQ0JzZ1lEVlIwUkJJR3FNSUducElHa01JR2hNVHN3T1FZRFZRUUVEREl4TFZSVFZId3lMVlJUVkh3ekxXVmtNakptTVdRNExXVTJZVEl0TVRFeE9DMDVZalU0TFdRNVlUaG1NVEZsTkRRMVpqRWZNQjBHQ2dtU0pvbVQ4aXhrQVFFTUR6TXdNRGszTURnd05qRXdNREF3TXpFTk1Bc0dBMVVFREF3RU1URXhNVEVSTUE4R0ExVUVHZ3dJVWxKU1JESTVNamt4SHpBZEJnTlZCQThNRmxKbFlXd2daWE4wWVhSbElHRmpkR2wyYVhScFpYTXdDZ1lJS29aSXpqMEVBd0lEUndBd1JBSWdXTEVydWI0Sm5LQWpiLzByNGpXM3JIVm9KeHM2V3RqbkY2T2hXa1R2Z013Q0lGbkcvbGxHRk5sc0VraytTVXR5U25WU1UzS2RTdHRURlg3VVRucnlmOGZB"
                    with open(f"cert.pem", 'w') as file:   #attaching X509 certificate
                        file.write(base64.b64decode(binarySecurityToken).decode('utf-8'))
                except Exception as e:
                    frappe.throw( "error in compliance x509" + str(e) )
                    

def sign_invoice():
                try:
                    settings=frappe.get_doc('Zatca setting')
                    xmlfile_name = 'finalzatcaxml.xml'
                    signed_xmlfile_name = 'sdsign.xml'
                    SDK_ROOT= settings.sdk_root
                    path_string=f"export SDK_ROOT={SDK_ROOT} && export FATOORA_HOME=$SDK_ROOT/Apps && export SDK_CONFIG=$SDK_ROOT/Configuration/config.json && export PATH=$PATH:$FATOORA_HOME &&  "
                    command_sign_invoice = path_string  + f'fatoora -sign -invoice {xmlfile_name} -signedInvoice {signed_xmlfile_name}'
                except Exception as e:
                    frappe.throw("An error occurred1 : " + str(e))
                
                try:
                    err,out = _execute_in_shell(command_sign_invoice)
                    
                    match = re.search(r'ERROR', err.decode("utf-8"))
                    if match:
                        frappe.throw(err)

                    match = re.search(r'ERROR', out.decode("utf-8"))
                    if match:
                        frappe.throw(out)
                    
                    match = re.search(r'INVOICE HASH = (.+)', out.decode("utf-8"))
                    if match:
                        invoice_hash = match.group(1)
                        frappe.msgprint("Xml file signed successfully and formed the signed xml invoice hash as : " + invoice_hash)
                        return signed_xmlfile_name , path_string
                    else:
                        frappe.throw(err,out)
                except Exception as e:
                    frappe.throw("An error occurred sign invoice : " + str(e))
            
def generate_qr_code(signed_xmlfile_name,sales_invoice_doc,path_string):
                try:
                    with open(signed_xmlfile_name, 'r') as file:
                        file_content = file.read()
                    command_generate_qr =path_string  + f'fatoora -qr -invoice {signed_xmlfile_name}'
                    err,out = _execute_in_shell(command_generate_qr)
                    qr_code_match = re.search(r'QR code = (.+)', out.decode("utf-8"))
                    if qr_code_match:
                        qr_code_value = qr_code_match.group(1)
                        frappe.msgprint("QR Code Value: " + qr_code_value)
                        file = frappe.get_doc({
                            "doctype": "File",
                            "file_name": "QR value file" + sales_invoice_doc.name,
                            "attached_to_doctype": sales_invoice_doc.doctype,
                            "attached_to_name": sales_invoice_doc.name,
                            "content": qr_code_value,
                        })
                        file.save()  
                    else:
                        frappe.msgprint("QR Code not found in the output.")    
                except Exception as e:
                    frappe.throw(f"Errorin generating qr:{e} ")
                    return None

           
def generate_hash(signed_xmlfile_name,path_string):
                try:
                    command_generate_hash = path_string  + f'fatoora -generateHash -invoice {signed_xmlfile_name}'
                    err,out = _execute_in_shell(command_generate_hash)
                    invoice_hash_match = re.search(r'INVOICE HASH = (.+)', out.decode("utf-8"))
                    if invoice_hash_match:
                        hash_value = invoice_hash_match.group(1)
                        frappe.msgprint("The hash value: " + hash_value)
                        return hash_value
                    else:
                        frappe.msgprint("Hash value not found in the log entry.")
                except Exception as e:
                    frappe.throw(f"Error in generate hash:{e} ")
                        
def validate_invoice(signed_xmlfile_name,path_string):               
                try:
                        command_validate_hash = path_string  + f'fatoora -validate -invoice {signed_xmlfile_name}'
                        err,out = _execute_in_shell(command_validate_hash)
                        pattern_global_result = re.search(r'\*\*\* GLOBAL VALIDATION RESULT = (\w+)', out.decode("utf-8"))
                        global_result = pattern_global_result.group(1) if pattern_global_result else None
                        global_validation_result = 'PASSED' if global_result == 'PASSED' else 'FAILED'
                        if global_validation_result == 'FAILED':
                            
                            frappe.msgprint(out)
                            frappe.msgprint(err)
                            frappe.msgprint("Validation has been failed")
                        else:
                            frappe.msgprint(out)
                            frappe.msgprint(err)
                            frappe.msgprint("Validation has been done Successfully")
                except Exception as e:
                            frappe.throw(f"An error occurred validate invoice: {str(e)}")  
               
def get_Clearance_Status(result):
                    try:
                        json_data = json.loads(result.text)
                        clearance_status = json_data.get("clearanceStatus")
                        print("clearance status: " + clearance_status)
                        return clearance_status
                    except Exception as e:
                        print(e) 
                        
def xml_base64_Decode(signed_xmlfile_name):
                    try:
                        with open(signed_xmlfile_name, "r") as file:
                                        xml = file.read().lstrip()
                                        base64_encoded = base64.b64encode(xml.encode("utf-8"))
                                        base64_decoded = base64_encoded.decode("utf-8")
                                        return base64_decoded
                    except Exception as e:
                        frappe.throw("error in xml base64 " + str(e) )


def send_invoice_for_clearance_normal(uuid1, signed_xmlfile_name, hash_value):
                try:
                    settings = frappe.get_doc('Zatca setting')
                    payload = json.dumps({
                        "invoiceHash": hash_value,
                        "uuid": uuid1,
                        "invoice": xml_base64_Decode(signed_xmlfile_name) })
                    headers = {
                        'accept': 'application/json',
                        'Accept-Language': 'en',
                        'Accept-Version': 'V2',
                        'Authorization': "Basic" + settings.basic_auth,
                        'Content-Type': 'application/json'  }
                    settings.pih = hash_value
                    settings.save()
                    try:
                        response = requests.request("POST", url=get_API_url(base_url="compliance/invoices"), headers=headers, data=payload)
                        # frappe.msgprint(response.text)
                        frappe.msgprint(response.text)
                        return response.text, get_Clearance_Status(response)
                    except Exception as e:
                        frappe.msgprint(str(e))
                        return "error", "NOT_CLEARED"
                except Exception as e:
                    frappe.throw("error in clearance invoice ,zatca validation" + str(e) )

@frappe.whitelist(allow_guest=True)                   
def production_CSID():
                # frappe.throw("production_CSID")
                
                try:
                    settings = frappe.get_doc('Zatca setting')
                    # frappe.msgprint(settings.basic_auth)
                    payload = json.dumps({
                    "compliance_request_id": settings.compliance_request_id })
                   
                    headers = {
                    'accept': 'application/json',
                    'Accept-Version': 'V2',
                    'Authorization': 'Basic'+ settings.basic_auth,
                    # 'Authorization': 'Basic'+ "VkZWc1NsRXhTalpSTUU1Q1dsaHNibEZZWkVwUmEwWnVVMVZrUWxkWWJGcFhhazAxVTJzeFFtSXdaRVJSTTBaSVZUQXdNRTlWU2tKVVZVNU9VV3hXTkZKWWNFSlZhMHB1Vkd4YVExRlZNVTVSTWpGWFUyMUtkVmR1V21oV01EVjNXVzB4YW1Rd2FHOVpNRFZPWVdzeE5GUlhjRXBsYXpGeFVWaHdVRlpGYkRaV01taHFWR3N4Y1ZvemFFNWhhMncxVkZkd1JtUXdNVVZSV0dSWVlXdEpNVlJXUm5wa01FNVNWMVZTVjFWV1JraFNXR1JMVmtaR1ZWSldiRTVSYkd4SVVWUkdWbEpWVGpOa01VSk9aV3RHTTFReFVtcGtNRGxGVVZSS1RsWkZSak5VVlZKQ1pXc3hWRm96WkV0YU1XeEZWbXhHVWxNd1VrTlBWVXBzVWpKNE5sTlZWbk5rVjAxNlVXMTRXazB4U25kWmFra3dXakZGZVU5WVZtdFRSWEJ2VjFST1UyTkhTblJaTW1SVVlrVTFSVlJXVGxwa01IQkNWMVZTVjFWV1JrVlNSVWw0VmxaVmVGVllVbEJTUjJONVZHdFNUbVZGTVZWVlZFWk5Wa1V4TTFSVlVuSk5NREZGV2pOa1QyRnJWak5VVlZKQ1pEQXhObEZzWkU1UmEwWklVVzVzZUZJeFRrNU9SR3hDV2pCV1NGRnNUakZSYTBwQ1VWVjBRazFGYkVKUmEzaFNZVWhDV1UxRlNrVmtSVVpTVDFWS05rOUhaM2ROYms1M1ZrWkdTbFZWVGpKT1YyYzBWRmhHTkdGRVVuQlRSVEYzVVcwNGRsRnRPWEJXUm1ScllsTjBVMWRYV2t0aVZYQlBaR3BrV1dSdVZUVk5NbHAyVjFjME1FNVVhRTlTTVVwdVltNW5NazVIV2xkaGJUbFdUREZDTVdGdFpHcFhXR1J1V1RBeE0xSkZSbHBTUmxwVFRVWlNRbFZWWjNaUmEwWktaREJHUlZFd1NucGFNV3hGVm14SmQxVnJTa3BTTTBaT1UxVmtkV05GYkVoaE1ERktVakpvVGxaSVRqTlVNVVphVWtaYVVsVlZWa1ZTUld3MFZFWmFVMVpHV2tsa00yeE5WbXhLVlZacmFETmxhM2hZVm0xMFRtRnJjSFJVVm1SU1RrVjRXRlpVU2xwV1JXd3dWRlpTUm1WRk9VUk5SRlphWVd4Vk1GUkdaRkpPVm14VllVY3hUbFpGV25OVWExSlNUVlp3Y1ZKWFdrNVJha0pJVVRKa2RGVXdjSFppVmxFMFlWaG9jbEZXUmtaVVZWSTJWRmhrVGxKSGMzcFVWVkp1WkRBMWNWSllaRTVTUlVZelZGaHdSbFJyTVVKak1HUkNUVlpXUmxKRlJqTlNWVEZWVWxob1RsWkZWbE5VVlVVMFVqQkZlRlpWVmtoYU0yUktWbGQ0UzFVeFNrVlRWRlpPWVcxME5GTkljRUphUlVwdVZHeGFRMUZVYUU1U2JYaExZa1pzV0dReVpHRlhSVFIzVjFab1UySkZiRWhTYlhCclVqSjNlVmxXYUZOalJuQlpWRmhrUkZveGJFcFRNamxoVTFod2NVMUZWa0prTUd4RlZURkdRbVF4U201VFYyaENWRmhHVTFOclJYSlZSRTVKVkVac2FWUXdNRFJPVldoTFRETmtUMlZ0UmxkT01XUnFXbTVKZGxkcVRqRmpWR3hMVFRCV1ZHTnNXbHBsYTBad1VsVkdkazV0YUdwUFZGSlRVMGR3YldRelRuZFpVemwzVjBaYWRWWnBPWFpWVjBaT1QxUk9hVTVzU1RKaVYyUmhWMFJDTVZGV1RYbE5WVnB1VUZFOVBRPT06eXRabHl6YklXY0wrUHlETytFd1JqWHRHSEp4SHB3cXdJYUVsaGxMQVJZQT0=",
                    # 'Authorization': 'Basic'+ "VFVsSlExSjZRME5CWlhsblFYZEpRa0ZuU1VkQldYbFpXak01U2sxQmIwZERRM0ZIVTAwME9VSkJUVU5OUWxWNFJYcEJVa0puVGxaQ1FVMU5RMjFXU21KdVduWmhWMDV3WW0xamQwaG9ZMDVOYWsxNFRXcEplazFxUVhwUFZFbDZWMmhqVGsxcVozaE5ha2w1VFdwRmQwMUVRWGRYYWtJMVRWRnpkME5SV1VSV1VWRkhSWGRLVkZGVVJWbE5RbGxIUVRGVlJVTjNkMUJOZWtGM1QxUmpkMDlFUVRKTlZFRjNUVVJCZWsxVFozZEtaMWxFVmxGUlMwUkNPVUpsUjJ4NlNVVnNkV016UW14Wk0xSndZakkwWjFFeU9YVmtTRXBvV1ROU2NHSnRZMmRUYkU1RVRWTlpkMHBCV1VSV1VWRkVSRUl4VlZVeFVYUlBSR2N5VGtSTmVFMVVVVEZNVkUxM1RVUnJNMDFFWjNkT2FrVjNUVVJCZDAxNlFsZE5Ra0ZIUW5seFIxTk5ORGxCWjBWSFFsTjFRa0pCUVV0Qk1FbEJRa3hSYUhCWU1FSkVkRUZST1VKNk9HZ3dNbk53VkZGSlVVTjJOV2c0VFhGNGFEUnBTRTF3UW04dlFtOXBWRmRrYlN0U1dXWktiVXBPZGpkWWRuVTVNMlp2V1c0ME5UaE9SMUpuYm5nMk5HWldhbTlWTDFCMWFtZGpXWGRuWTAxM1JFRlpSRlpTTUZSQlVVZ3ZRa0ZKZDBGRVEwSnpaMWxFVmxJd1VrSkpSM0ZOU1VkdWNFbEhhMDFKUjJoTlZITjNUMUZaUkZaUlVVVkVSRWw0VEZaU1ZGWklkM2xNVmxKVVZraDNla3hYVm10TmFrcHRUVmRSTkV4WFZUSlpWRWwwVFZSRmVFOURNRFZaYWxVMFRGZFJOVmxVYUcxTlZFWnNUa1JSTVZwcVJXWk5RakJIUTJkdFUwcHZiVlE0YVhoclFWRkZUVVI2VFhkTlJHc3pUVVJuZDA1cVJYZE5SRUYzVFhwRlRrMUJjMGRCTVZWRlJFRjNSVTFVUlhoTlZFVlNUVUU0UjBFeFZVVkhaM2RKVld4S1UxSkVTVFZOYW10NFNIcEJaRUpuVGxaQ1FUaE5SbXhLYkZsWGQyZGFXRTR3V1ZoU2JFbEhSbXBrUjJ3eVlWaFNjRnBZVFhkRFoxbEpTMjlhU1hwcU1FVkJkMGxFVTFGQmQxSm5TV2hCVFhGU1NrRXJVRE5JVEZsaVQwMDROVWhLTDNkT2VtRldOMWRqWm5JdldqTjFjVGxLTTBWVGNsWlpla0ZwUlVGdk5taGpPVFJTU0dwbWQzTndZUzl3V0ZadVZpOXZVV0ZOT1ROaU5sSTJiV2RhV0RCMVFWTXlNVVpuUFE9PTp5dFpseXpiSVdjTCtQeURPK0V3UmpYdEdISnhIcHdxd0lhRWxobExBUllBPQ==",
                    'Content-Type': 'application/json' }
                    
                    response = requests.request("POST", url=get_API_url(base_url="production/csids"), headers=headers, data=payload)
                    if response.status_code != 200:
                        frappe.throw("Error: " + str(response.text))
                    data=json.loads(response.text)
                    concatenated_value = data["binarySecurityToken"] + ":" + data["secret"]
                    encoded_value = base64.b64encode(concatenated_value.encode()).decode()
                    with open(f"cert.pem", 'w') as file:   #attaching X509 certificate
                        file.write(base64.b64decode(data["binarySecurityToken"]).decode('utf-8'))
                    settings.set("basic_auth_production", encoded_value)
                    settings.save()
                except Exception as e:
                    frappe.throw("error in  production csid formation" + str(e) )

def get_Reporting_Status(result):
                        try:
                            json_data = json.loads(result.text)
                            reporting_status = json_data.get("reportingStatus")
                            print("reportingStatus: " + reporting_status)
                            return reporting_status
                        except Exception as e:
                            print(e) 

def reporting_API(uuid1,hash_value,signed_xmlfile_name):
                # frappe.msgprint(xml_base64_Decode(signed_xmlfile_name))
                try:
                    settings = frappe.get_doc('Zatca setting')
                    payload = json.dumps({
                    "invoiceHash": hash_value,
                    "uuid": uuid1,
                    "invoice": xml_base64_Decode(signed_xmlfile_name),
                    })
                    headers = {
                    'accept': 'application/json',
                    'accept-language': 'en',
                    'Clearance-Status': '0',
                    'Accept-Version': 'V2',
                    # 'Authorization': "Basic VFVsSlJESjZRME5CTkVOblFYZEpRa0ZuU1ZSaWQwRkJaSEZFYlVsb2NYTnFjRzAxUTNkQlFrRkJRakp2UkVGTFFtZG5jV2hyYWs5UVVWRkVRV3BDYWsxU1ZYZEZkMWxMUTFwSmJXbGFVSGxNUjFGQ1IxSlpSbUpIT1dwWlYzZDRSWHBCVWtKbmIwcHJhV0ZLYXk5SmMxcEJSVnBHWjA1dVlqTlplRVo2UVZaQ1oyOUthMmxoU21zdlNYTmFRVVZhUm1ka2JHVklVbTVaV0hBd1RWSjNkMGRuV1VSV1VWRkVSWGhPVlZVeGNFWlRWVFZYVkRCc1JGSlRNVlJrVjBwRVVWTXdlRTFDTkZoRVZFbDVUVVJOZVU5RVJURk9SRmw2VFd4dldFUlVTWGxOUkUxNlRVUkZNVTVFV1hwTmJHOTNWRlJGVEUxQmEwZEJNVlZGUW1oTlExVXdSWGhFYWtGTlFtZE9Wa0pCYjFSQ1ZYQm9ZMjFzZVUxU2IzZEhRVmxFVmxGUlRFVjRSa3RhVjFKcldWZG5aMUZ1U21oaWJVNXZUVlJKZWs1RVJWTk5Ra0ZIUVRGVlJVRjRUVXBOVkVrelRHcEJkVTFETkhoTlJsbDNSVUZaU0V0dldrbDZhakJEUVZGWlJrczBSVVZCUVc5RVVXZEJSVVF2ZDJJeWJHaENka0pKUXpoRGJtNWFkbTkxYnpaUGVsSjViWGx0VlRsT1YxSm9TWGxoVFdoSFVrVkNRMFZhUWpSRlFWWnlRblZXTW5oWWFYaFpOSEZDV1dZNVpHUmxjbnByVnpsRWQyUnZNMGxzU0dkeFQwTkJhVzkzWjJkSmJVMUpSMHhDWjA1V1NGSkZSV2RaVFhkbldVTnJabXBDT0UxU2QzZEhaMWxFVmxGUlJVUkNUWGxOYWtsNVRXcE5lVTVFVVRCTmVsRjZZVzFhYlU1RVRYbE5VamgzU0ZGWlMwTmFTVzFwV2xCNVRFZFJRa0ZSZDFCTmVrVjNUVlJqTVUxNmF6Tk9SRUYzVFVSQmVrMVJNSGREZDFsRVZsRlJUVVJCVVhoTlJFVjRUVkpGZDBSM1dVUldVVkZoUkVGb1ZGbFhNWGRpUjFWblVsUkZXazFDWTBkQk1WVkZSSGQzVVZVeVJuUmpSM2hzU1VWS01XTXpUbkJpYlZaNlkzcEJaRUpuVGxaSVVUUkZSbWRSVldoWFkzTmlZa3BvYWtRMVdsZFBhM2RDU1V4REszZE9WbVpMV1hkSWQxbEVWbEl3YWtKQ1ozZEdiMEZWWkcxRFRTdDNZV2R5UjJSWVRsb3pVRzF4ZVc1TE5Xc3hkRk00ZDFSbldVUldVakJtUWtWamQxSlVRa1J2UlVkblVEUlpPV0ZJVWpCalJHOTJURE5TZW1SSFRubGlRelUyV1ZoU2FsbFROVzVpTTFsMVl6SkZkbEV5Vm5sa1JWWjFZMjA1YzJKRE9WVlZNWEJHVTFVMVYxUXdiRVJTVXpGVVpGZEtSRkZUTUhoTWJVNTVZa1JEUW5KUldVbExkMWxDUWxGVlNFRlJSVVZuWVVGM1oxb3dkMkpuV1VsTGQxbENRbEZWU0UxQlIwZFpiV2d3WkVoQk5reDVPVEJqTTFKcVkyMTNkV1Z0UmpCWk1rVjFXakk1TWt4dVRtaE1NRTVzWTI1U1JtSnVTblppUjNkMlZrWk9ZVkpYYkhWa2JUbHdXVEpXVkZFd1JYaE1iVlkwWkVka2FHVnVVWFZhTWpreVRHMTRkbGt5Um5OWU1WSlVWMnRXU2xSc1dsQlRWVTVHVEZaT01WbHJUa0pNVkVWdlRWTnJkVmt6U2pCTlEzTkhRME56UjBGUlZVWkNla0ZDYUdnNWIyUklVbmRQYVRoMlpFaE9NRmt6U25OTWJuQm9aRWRPYUV4dFpIWmthVFY2V1ZNNWRsa3pUbmROUVRSSFFURlZaRVIzUlVJdmQxRkZRWGRKU0dkRVFXUkNaMDVXU0ZOVlJVWnFRVlZDWjJkeVFtZEZSa0pSWTBSQloxbEpTM2RaUWtKUlZVaEJkMDEzU25kWlNrdDNXVUpDUVVkRFRuaFZTMEpDYjNkSFJFRkxRbWRuY2tKblJVWkNVV05FUVdwQlMwSm5aM0pDWjBWR1FsRmpSRUY2UVV0Q1oyZHhhR3RxVDFCUlVVUkJaMDVLUVVSQ1IwRnBSVUY1VG1oNVkxRXpZazVzVEVaa1QxQnNjVmxVTmxKV1VWUlhaMjVMTVVkb01FNUlaR05UV1RSUVprTXdRMGxSUTFOQmRHaFlkblkzZEdWMFZVdzJPVmRxY0RoQ2VHNU1URTEzWlhKNFdtaENibVYzYnk5blJqTkZTa0U5UFE9PTpmOVlSaG9wTi9HN3gwVEVDT1k2bktTQ0hMTllsYjVyaUFIU0ZQSUNvNHF3PQ==" ,
                    # 'Authorization': "Basic VFVsSlJESjZRME5CTkVOblFYZEpRa0ZuU1ZSaWQwRkJaSEZFYlVsb2NYTnFjRzAxUTNkQlFrRkJRakp2UkVGTFFtZG5jV2hyYWs5UVVWRkVRV3BDYWsxU1ZYZEZkMWxMUTFwSmJXbGFVSGxNUjFGQ1IxSlpSbUpIT1dwWlYzZDRSWHBCVWtKbmIwcHJhV0ZLYXk5SmMxcEJSVnBHWjA1dVlqTlplRVo2UVZaQ1oyOUthMmxoU21zdlNYTmFRVVZhUm1ka2JHVklVbTVaV0hBd1RWSjNkMGRuV1VSV1VWRkVSWGhPVlZVeGNFWlRWVFZYVkRCc1JGSlRNVlJrVjBwRVVWTXdlRTFDTkZoRVZFbDVUVVJOZVU5RVJURk9SRmw2VFd4dldFUlVTWGxOUkUxNlRVUkZNVTVFV1hwTmJHOTNWRlJGVEUxQmEwZEJNVlZGUW1oTlExVXdSWGhFYWtGTlFtZE9Wa0pCYjFSQ1ZYQm9ZMjFzZVUxU2IzZEhRVmxFVmxGUlRFVjRSa3RhVjFKcldWZG5aMUZ1U21oaWJVNXZUVlJKZWs1RVJWTk5Ra0ZIUVRGVlJVRjRUVXBOVkVrelRHcEJkVTFETkhoTlJsbDNSVUZaU0V0dldrbDZhakJEUVZGWlJrczBSVVZCUVc5RVVXZEJSVVF2ZDJJeWJHaENka0pKUXpoRGJtNWFkbTkxYnpaUGVsSjViWGx0VlRsT1YxSm9TWGxoVFdoSFVrVkNRMFZhUWpSRlFWWnlRblZXTW5oWWFYaFpOSEZDV1dZNVpHUmxjbnByVnpsRWQyUnZNMGxzU0dkeFQwTkJhVzkzWjJkSmJVMUpSMHhDWjA1V1NGSkZSV2RaVFhkbldVTnJabXBDT0UxU2QzZEhaMWxFVmxGUlJVUkNUWGxOYWtsNVRXcE5lVTVFVVRCTmVsRjZZVzFhYlU1RVRYbE5VamgzU0ZGWlMwTmFTVzFwV2xCNVRFZFJRa0ZSZDFCTmVrVjNUVlJqTVUxNmF6Tk9SRUYzVFVSQmVrMVJNSGREZDFsRVZsRlJUVVJCVVhoTlJFVjRUVkpGZDBSM1dVUldVVkZoUkVGb1ZGbFhNWGRpUjFWblVsUkZXazFDWTBkQk1WVkZSSGQzVVZVeVJuUmpSM2hzU1VWS01XTXpUbkJpYlZaNlkzcEJaRUpuVGxaSVVUUkZSbWRSVldoWFkzTmlZa3BvYWtRMVdsZFBhM2RDU1V4REszZE9WbVpMV1hkSWQxbEVWbEl3YWtKQ1ozZEdiMEZWWkcxRFRTdDNZV2R5UjJSWVRsb3pVRzF4ZVc1TE5Xc3hkRk00ZDFSbldVUldVakJtUWtWamQxSlVRa1J2UlVkblVEUlpPV0ZJVWpCalJHOTJURE5TZW1SSFRubGlRelUyV1ZoU2FsbFROVzVpTTFsMVl6SkZkbEV5Vm5sa1JWWjFZMjA1YzJKRE9WVlZNWEJHVTFVMVYxUXdiRVJTVXpGVVpGZEtSRkZUTUhoTWJVNTVZa1JEUW5KUldVbExkMWxDUWxGVlNFRlJSVVZuWVVGM1oxb3dkMkpuV1VsTGQxbENRbEZWU0UxQlIwZFpiV2d3WkVoQk5reDVPVEJqTTFKcVkyMTNkV1Z0UmpCWk1rVjFXakk1TWt4dVRtaE1NRTVzWTI1U1JtSnVTblppUjNkMlZrWk9ZVkpYYkhWa2JUbHdXVEpXVkZFd1JYaE1iVlkwWkVka2FHVnVVWFZhTWpreVRHMTRkbGt5Um5OWU1WSlVWMnRXU2xSc1dsQlRWVTVHVEZaT01WbHJUa0pNVkVWdlRWTnJkVmt6U2pCTlEzTkhRME56UjBGUlZVWkNla0ZDYUdnNWIyUklVbmRQYVRoMlpFaE9NRmt6U25OTWJuQm9aRWRPYUV4dFpIWmthVFY2V1ZNNWRsa3pUbmROUVRSSFFURlZaRVIzUlVJdmQxRkZRWGRKU0dkRVFXUkNaMDVXU0ZOVlJVWnFRVlZDWjJkeVFtZEZSa0pSWTBSQloxbEpTM2RaUWtKUlZVaEJkMDEzU25kWlNrdDNXVUpDUVVkRFRuaFZTMEpDYjNkSFJFRkxRbWRuY2tKblJVWkNVV05FUVdwQlMwSm5aM0pDWjBWR1FsRmpSRUY2UVV0Q1oyZHhhR3RxVDFCUlVVUkJaMDVLUVVSQ1IwRnBSVUY1VG1oNVkxRXpZazVzVEVaa1QxQnNjVmxVTmxKV1VWUlhaMjVMTVVkb01FNUlaR05UV1RSUVprTXdRMGxSUTFOQmRHaFlkblkzZEdWMFZVdzJPVmRxY0RoQ2VHNU1URTEzWlhKNFdtaENibVYzYnk5blJqTkZTa0U5UFE9PTpmOVlSaG9wTi9HN3gwVEVDT1k2bktTQ0hMTllsYjVyaUFIU0ZQSUNvNHF3PQ==",
                    # 'Authorization': 'Basic' + settings.basic_auth_production,
                    'Authorization': 'Basic' + settings.basic_auth_production,
                    'Content-Type': 'application/json',
                    'Cookie': 'TS0106293e=0132a679c0639d13d069bcba831384623a2ca6da47fac8d91bef610c47c7119dcdd3b817f963ec301682dae864351c67ee3a402866'
                    }
                    try:
                        response = requests.request("POST", url=get_API_url(base_url="invoices/reporting/single"), headers=headers, data=payload)
                        # response = requests.request("POST", url="https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal/invoices/reporting/single", headers=headers, data=payload)
                        frappe.msgprint("Reporting API response: " + response.text)
                        frappe.msgprint(response.text , get_Reporting_Status(response))
                    except Exception as e:    
                        frappe.msgprint(str(e)) 
                        frappe.msgprint ("error","NOT_REPORTED")
                except Exception as e:
                    frappe.msgprint ("error","NOT-REPORTED")
                    frappe.throw("error in reporting api" + str(e) )
                    
def clearance_API(uuid1,hash_value,signed_xmlfile_name):
                try:
                    settings = frappe.get_doc('Zatca setting')
                    payload = json.dumps({
                    "invoiceHash": hash_value,
                    "uuid": uuid1,
                    "invoice": xml_base64_Decode(signed_xmlfile_name), })
                    headers = {
                    'accept': 'application/json',
                    'accept-language': 'en',
                    'Clearance-Status': '1',
                    'Accept-Version': 'V2',
                    'Authorization': 'Basic' + settings.basic_auth_production,
                    'Content-Type': 'application/json',
                    'Cookie': 'TS0106293e=0132a679c03c628e6c49de86c0f6bb76390abb4416868d6368d6d7c05da619c8326266f5bc262b7c0c65a6863cd3b19081d64eee99' }
                    response = requests.request("POST", url=get_API_url(base_url="invoices/clearance/single"), headers=headers, data=payload)
                    frappe.msgprint(response.text)
                except Exception as e:
                    frappe.throw("error in clearance api" + str(e) )

def zatca_Call(invoice_number):
                    try:    
                            # create_compliance_x509()
                            # frappe.throw("Created compliance x509 certificate")
                            invoice= xml_tags()
                            invoice,uuid1,sales_invoice_doc=salesinvoice_data(invoice,invoice_number)
                            customer_doc= frappe.get_doc("Customer",sales_invoice_doc.customer)
                            if customer_doc.customer_type == "B2C":
                                invoice = invoice_Typecode_Simplified(invoice, sales_invoice_doc)
                            else:
                                invoice = invoice_Typecode_Standard(invoice, sales_invoice_doc)
                            invoice=doc_Reference(invoice,sales_invoice_doc,invoice_number)
                            
                            invoice=additional_Reference(invoice)
                            invoice=company_Data(invoice,sales_invoice_doc)
                            invoice=customer_Data(invoice,sales_invoice_doc)
                            invoice=delivery_And_PaymentMeans(invoice,sales_invoice_doc, sales_invoice_doc.is_return)
                            
                            invoice=tax_Data(invoice,sales_invoice_doc)
                            invoice=item_data(invoice,sales_invoice_doc)
                            pretty_xml_string=xml_structuring(invoice,sales_invoice_doc)
                            signed_xmlfile_name,path_string=sign_invoice()
                            generate_qr_code(signed_xmlfile_name,sales_invoice_doc,path_string)
                            hash_value =generate_hash(signed_xmlfile_name,path_string)
                            validate_invoice(signed_xmlfile_name,path_string)
                            # frappe.msgprint("validated and stopped it here")
                            # result,clearance_status=send_invoice_for_clearance_normal(uuid1,signed_xmlfile_name,hash_value)
                            if customer_doc.customer_type == "B2C":
                                reporting_API(uuid1, hash_value, signed_xmlfile_name)
                            else:
                                clearance_API(uuid1, hash_value, signed_xmlfile_name)
                            # current_time =now()
                            # if clearance_status == "CLEARED":
                            #     frappe.get_doc({"doctype":"Zatca Success log","title":"Zatca invoice call done successfully","message":"This message by Zatca Compliance ","uuid":uuid1,"invoice_number": invoice_number,"time":current_time,"zatca_response":result}).insert()    
                            # else:
                            #     frappe.log_error(title='Zatca invoice call failed in clearance status',message=frappe.get_traceback())
                            # return (json.dumps(result))
                    except:       
                            frappe.log_error(title='Zatca invoice call failed', message=frappe.get_traceback())
                
@frappe.whitelist(allow_guest=True)                        
def zatca_Background(invoice_number):
                      zatca_Call(invoice_number)
# #                     # frappe.enqueue(
#                     #         zatca_Call,
#                     #         queue="short",
#                     #         timeout=200,
#                     #         invoice_number=invoice_number)
#                     # frappe.msgprint("queued")


