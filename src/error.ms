if not globals.hasIndex("minicrypt") then minicrypt = {}

__scope = function //-------------

// Returns a map like {"classID": "error", "location": location, "code": code}. 'location' is the name of the function where the error originated from, and 'code' is a descriptive error string.
// @param {string} location
// @param {string} code
// @returns {map<string, string>}
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