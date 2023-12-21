// Copyright (c) 2023, ERPGulf and contributors
// For license information, please see license.txt

frappe.ui.form.on("Zatca setting", {
	refresh(frm) {
       
    },
    production_csid: function (frm) {
        frappe.call({
            method: "zatca2023.zatca2023.zatcasdkcode.production_CSID",
            args: {
              
            },
            callback: function (r) {
                if (!r.exc) {
                    frm.save();
                    window.open(r.message.url);
                }
            },
        });
    },
    csid_attach: function (frm) {
            frappe.call({
                method: "zatca2023.zatca2023.zatcasdkcode.create_CSID",
                args: {
                  
                },
                callback: function (r) {
                    if (!r.exc) {
                        frm.save();
                        window.open(r.message.url);
                    }
                },
            });
        },
    create_csr: function (frm) {
        frappe.call({
            method: "zatca2023.zatca2023.zatcasdkcode.generate_csr",
            args: {
              
            },
            callback: function (r) {
                if (!r.exc) {
                    frm.save();
                    window.open(r.message.url);
                }
            },
        });
    }
    
});
