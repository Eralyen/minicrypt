// Template for a new module
if not globals.hasIndex("minicrypt") then minicrypt = {}

__scope = function //-------------
locals.minicrypt = minicrypt

minicrypt.Template = {}                              // EDIT
Template = minicrypt.Template                        // EDIT

// Your code here

end function //-------------

if not minicrypt.hasIndex("Template") then __scope() // EDIT
globals.remove("__scope")