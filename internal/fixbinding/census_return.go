package fixbinding

import "go/ast"

// returnParameter checks the complete declaration body, not a saved summary.
// The supported return rule is intentionally closed: exactly `return param`,
// with one result and no statements that could mutate or escape the resource.
func returnParameter(fn *ast.FuncDecl) (int, bool) {
	if fn == nil || fn.Recv != nil || fn.Body == nil || len(fn.Body.List) != 1 {
		return 0, false
	}
	ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return 0, false
	}
	return parameterIndex(fn, ret.Results[0])
}

func (s *censusScan) returnedArgument(call *ast.CallExpr, res callResolution) (evalResult, bool) {
	if !res.Resolved || !res.Local {
		return evalResult{}, false
	}
	index, ok := returnParameter(res.Func)
	if !ok || index >= len(call.Args) {
		return evalResult{}, false
	}
	return s.eval(call.Args[index]), true
}
