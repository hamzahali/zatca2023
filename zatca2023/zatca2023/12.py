import frappe
import os
frappe.init(site="prod.erpgulf.com")
frappe.connect()

invoice_number="ACC-SINV-2023-00007"
sales_invoice_doc = frappe.get_doc('Sales Invoice' ,invoice_number)
customer_doc= frappe.get_doc("Customer",sales_invoice_doc.customer)
# address = customer_doc.customer_primary_address
if int(frappe.__version__.split('.')[0]) == 15:
                    address = frappe.get_doc("Address", customer_doc.customer_primary_address)    
else:
    address = frappe.get_doc("Address", customer_doc.customer_address)

cbc_StreetName = address.address_line1

cbc_BuildingNumber = address.address_line2

if hasattr(address, 'po_box'):
    cbc_Plot= address.po_box
else:
    cbc_Plot = address.address_line1


cbc_City = address.address_line2

cbc_City= address.city

cbc_Pos =address.pincode
print(cbc_Plot)
# address= frappe.get_doc("Address",customer_doc.customer_primary_address)
print(frappe.__version__)
print(address)
print(customer_doc)
street=address.address_line1
print(street)


