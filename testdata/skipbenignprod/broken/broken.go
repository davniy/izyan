package broken

// This package fails to type-check without importing the subject module: no
// reference to the module's symbols can hide behind it, so a module-scoped
// proof is not opened by its exclusion.
func Broken() int { return undefinedIdentifier }
