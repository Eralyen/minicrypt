if not globals.hasIndex("minicrypt") then minicrypt = {}

__scope = function //-------------

minicrypt.Error = function(location, code)
    return {
        "classID": "error",
        "location": location,
        "code": code,
    }
end function

end function //-------------

if not minicrypt.hasIndex("Error") then __scope()
globals.remove("__scope")