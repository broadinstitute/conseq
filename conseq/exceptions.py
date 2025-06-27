"""
Consolidated exception classes for the conseq package.
"""


class MissingObj(Exception):
    """Raised when a required object cannot be found."""
    pass


class FatalUserError(Exception):
    """Raised when a fatal user error occurs that should stop execution."""
    pass

class MissingTemplateVar(Exception):
    """Raised when a required template variable is missing."""
    
    def __init__(self, message, variables, template):
        super(MissingTemplateVar, self).__init__()
        self.variables = variables
        self.template = template
        self.message = message

    def get_error(self):
        var_defs = []
        for k, v in self.variables.items():
            if isinstance(v, dict):
                var_defs.append("  {}:".format(repr(k)))
                for k2, v2 in v.items():
                    var_defs.append("    {}: {}".format(repr(k2), repr(v2)))
            else:
                var_defs.append("  {}: {}".format(repr(k), repr(v)))

        var_block = "".join(x + "\n" for x in var_defs)
        return "Template error: {}, applying vars:\n{}\n to template:\n{}".format(
            self.message, var_block, self.template
        )
