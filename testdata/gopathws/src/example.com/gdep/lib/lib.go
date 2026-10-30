package lib

// Used is the benign API the product calls.
func Used() string { return "ok" }

// Vulnerable is invoked at package init by the sibling caller package —
// unreachable from the product but visible to the module cone. With no
// module metadata the cone cannot even be built.
func Vulnerable() string { return "vuln" }
