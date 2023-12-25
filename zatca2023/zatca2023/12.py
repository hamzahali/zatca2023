import frappe
import os
frappe.init(site="prod.erpgulf.com")
frappe.connect()
invoice_number="ACC-SINV-2023-00007"
sales_invoice_doc = frappe.get_doc('Sales Invoice' ,invoice_number)
company_doc = frappe.get_doc("Company", sales_invoice_doc.company)
address = frappe.get_doc("Address", company_doc)    
addresscomp= frappe.get_list(address,filters={"is_your_company_address":"1"},fields=["address_line1","address_line2"])
print(addresscomp)
# address = company_doc.address_html

print(address)