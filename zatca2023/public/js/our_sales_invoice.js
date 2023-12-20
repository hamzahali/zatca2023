frappe.ui.form.on("Sales Invoice", {
    refresh: function(frm) {
        frm.add_custom_button(__("click"), function() {
            frm.call({
                method:"zatca2023.zatca2023.zatcasdkcode.zatca_Background",
                args: {
                    "invoice_number": frm.doc.name
                },
                callback: function(response) {
                    if (response.message) {  
                        frappe.msgprint(response.message);  
                    }
                }
            });
        }, __("sale invoice buttton click"));
    }
});
