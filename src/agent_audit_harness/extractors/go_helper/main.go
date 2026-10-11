// Extract typed call sites without running target programs, generators or tests.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/tools/go/packages"
)

type row = map[string]any

type extractor struct {
	root         string
	functions    []row
	calls        []row
	symbols      map[string][]string
	literals     map[*ast.FuncLit]string
	owners       map[*ast.FuncDecl]string
	contexts     []row
	objects      map[types.Object]string
	preambles    map[*ast.File]string
	declarations map[*ast.GenDecl][]row
}

func identity(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func qualifier(pkg *types.Package) string { return pkg.Path() }

func symbol(fn *types.Func) (string, string) {
	fn = fn.Origin()
	prefix := fn.Pkg().Path()
	parts := []string{prefix, "", fn.Name()}
	if receiver := fn.Type().(*types.Signature).Recv(); receiver != nil {
		typ := types.Unalias(receiver.Type())
		if pointer, ok := typ.(*types.Pointer); ok {
			typ = types.Unalias(pointer.Elem())
		}
		if named, ok := typ.(*types.Named); ok {
			parts[1] = named.Obj().Name()
			prefix += "." + named.Obj().Name()
		}
	}
	return strings.Join(parts, "\x00"), prefix + "." + fn.Name()
}

func (e *extractor) location(pkg *packages.Package, pos token.Pos) (string, token.Position) {
	position := pkg.Fset.PositionFor(pos, false)
	path, err := filepath.Rel(e.root, position.Filename)
	if err != nil || path == ".." || strings.HasPrefix(path, ".."+string(filepath.Separator)) {
		panic("source position outside snapshot")
	}
	return filepath.ToSlash(path), position
}

func (e *extractor) definition(pkg *packages.Package, node ast.Node, name, qualified, kind string, sig *types.Signature) string {
	path, start := e.location(pkg, node.Pos())
	_, end := e.location(pkg, node.End()-1)
	id := identity("go", qualified, path, fmt.Sprint(start.Offset))
	params := []row{}
	for i := 0; i < sig.Params().Len(); i++ {
		param := sig.Params().At(i)
		params = append(params, row{"name": param.Name(), "type": types.TypeString(param.Type(), qualifier)})
	}
	e.functions = append(e.functions, row{
		"id": id, "language": "go", "scope": pkg.PkgPath, "kind": kind,
		"name": name, "qualified_name": qualified, "signature": types.TypeString(sig, qualifier),
		"path": path, "line": start.Line, "end_line": end.Line, "parameters": params,
		"column": start.Column, "end_column": end.Column,
	})
	return id
}

func unwrap(expr ast.Expr) ast.Expr {
	for {
		switch value := expr.(type) {
		case *ast.ParenExpr:
			expr = value.X
		case *ast.IndexExpr:
			expr = value.X
		case *ast.IndexListExpr:
			expr = value.X
		default:
			return expr
		}
	}
}

func isInterface(typ types.Type) bool {
	return typ != nil && types.IsInterface(typ)
}

func (e *extractor) context(pkg *packages.Package, node ast.Node, name, kind string, pos token.Pos) string {
	path, start := e.location(pkg, node.Pos())
	_, end := e.location(pkg, node.End()-1)
	id := identity("go-context", pkg.PkgPath, name, path, fmt.Sprint(pkg.Fset.PositionFor(pos, false).Offset))
	e.contexts = append(e.contexts, row{"id": id, "language": "go", "scope": pkg.PkgPath,
		"kind": kind, "name": name, "path": path, "line": start.Line, "end_line": end.Line,
		"references": []string{}})
	return id
}

func (e *extractor) references(pkg *packages.Package, node ast.Node, preamble string) []string {
	seen := map[string]bool{}
	if preamble != "" {
		seen[preamble] = true
	}
	ast.Inspect(node, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok {
			if id := e.objects[pkg.TypesInfo.Uses[ident]]; id != "" {
				seen[id] = true
			}
		}
		return true
	})
	ids := []string{}
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (e *extractor) functionArgument(pkg *packages.Package, expr ast.Expr, index int) row {
	expr = unwrap(expr)
	var object types.Object
	name, status, reason := "<function value>", "unresolved", "function_value"
	var id any
	indirect := false
	switch value := expr.(type) {
	case *ast.Ident:
		name, object = value.Name, pkg.TypesInfo.Uses[value]
	case *ast.SelectorExpr:
		name = value.Sel.Name
		if selection := pkg.TypesInfo.Selections[value]; selection != nil {
			object, indirect = selection.Obj(), isInterface(selection.Recv())
		} else {
			object = pkg.TypesInfo.Uses[value.Sel]
		}
	case *ast.FuncLit:
		if literal := e.literals[value]; literal != "" {
			id, status, reason = literal, "resolved", ""
		}
	}
	if fn, ok := object.(*types.Func); ok {
		key, qualified := symbol(fn)
		name = qualified
		if receiver := fn.Type().(*types.Signature).Recv(); receiver != nil {
			indirect = indirect || isInterface(receiver.Type())
		}
		matches := e.symbols[key]
		switch {
		case indirect:
			reason = "interface_dispatch"
		case len(matches) == 1:
			id, status, reason = matches[0], "resolved", ""
		case len(matches) == 0:
			status, reason = "external", "definition_outside_extracted_scope"
		default:
			status, reason = "ambiguous", "multiple_definitions"
		}
	}
	return row{"index": index, "function": id, "name": name, "status": status, "reason": reason}
}

func (e *extractor) call(pkg *packages.Package, caller string, call *ast.CallExpr, execution string) {
	// Conversions are expressions; their argument calls are still visited.
	if pkg.TypesInfo.Types[call.Fun].IsType() {
		return
	}
	expr := unwrap(call.Fun)
	path, position := e.location(pkg, call.Pos())
	name, dispatch, status, reason := "<function value>", "function_value", "unresolved", "function_value"
	var callee any
	var object types.Object
	interfaceDispatch := false
	switch value := expr.(type) {
	case *ast.Ident:
		name, object = value.Name, pkg.TypesInfo.Uses[value]
	case *ast.SelectorExpr:
		name = value.Sel.Name
		if selection := pkg.TypesInfo.Selections[value]; selection != nil {
			object = selection.Obj()
			interfaceDispatch = isInterface(selection.Recv())
		} else {
			object = pkg.TypesInfo.Uses[value.Sel]
		}
	case *ast.FuncLit:
		name, dispatch, status, reason = "<function literal>", "direct", "resolved", ""
		callee = e.literals[value]
	}
	switch value := object.(type) {
	case *types.Func:
		key, qualified := symbol(value)
		name = qualified
		if receiver := value.Type().(*types.Signature).Recv(); receiver != nil {
			interfaceDispatch = interfaceDispatch || isInterface(receiver.Type())
		}
		if interfaceDispatch {
			dispatch, status, reason = "interface", "unresolved", "interface_dispatch"
		} else {
			dispatch = "direct"
			matches := e.symbols[key]
			switch len(matches) {
			case 0:
				status, reason = "external", "definition_outside_extracted_scope"
			case 1:
				callee, status, reason = matches[0], "resolved", ""
			default:
				status, reason = "ambiguous", "multiple_definitions"
			}
		}
	case *types.Builtin:
		dispatch, status, reason = "builtin", "external", "builtin"
	}
	arguments := []row{}
	for index, argument := range call.Args {
		typ := pkg.TypesInfo.TypeOf(argument)
		if typ != nil {
			if _, ok := typ.Underlying().(*types.Signature); ok {
				arguments = append(arguments, e.functionArgument(pkg, argument, index))
			}
		}
	}
	e.calls = append(e.calls, row{
		"id":       identity(caller, path, fmt.Sprint(position.Offset), name, status, execution),
		"language": "go", "caller": caller, "callee": callee, "callee_name": name,
		"path": path, "line": position.Line, "column": position.Column,
		"kind": "call", "dispatch": dispatch, "execution": execution,
		"status": status, "reason": reason, "provenance": "go_types",
		"function_arguments": arguments,
	})
}

func (e *extractor) walk(pkg *packages.Package, body *ast.BlockStmt, owner string) {
	executions := map[*ast.CallExpr]string{}
	ast.Inspect(body, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.FuncLit:
			e.walk(pkg, value.Body, e.literals[value])
			return false
		case *ast.GoStmt:
			executions[value.Call] = "concurrent"
		case *ast.DeferStmt:
			executions[value.Call] = "deferred"
		case *ast.CallExpr:
			// Compile-time calls (e.g. unsafe.Sizeof) do not evaluate operands.
			if pkg.TypesInfo.Types[value].Value != nil {
				return false
			}
			execution := executions[value]
			if execution == "" {
				execution = "normal"
			}
			e.call(pkg, owner, value, execution)
		}
		return true
	})
}

func extract(root string) (row, error) {
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return nil, err
	}
	module, err := modfile.Parse("go.mod", data, nil)
	if err != nil || module.Module == nil {
		return nil, fmt.Errorf("invalid go.mod: %v", err)
	}
	for _, replace := range module.Replace {
		if replace.New.Version == "" {
			return nil, fmt.Errorf("local Go replacements are unsupported: %s", replace.Old.Path)
		}
	}
	pkgs, err := packages.Load(&packages.Config{
		Mode: packages.LoadSyntax | packages.NeedModule, Dir: root, Env: os.Environ(),
	}, "./...")
	if err != nil {
		return nil, err
	}
	if len(pkgs) == 0 || len(pkgs) > 256 {
		return nil, fmt.Errorf("Go extraction requires 1..256 packages")
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].PkgPath < pkgs[j].PkgPath })
	e := extractor{root: root, functions: []row{}, calls: []row{}, symbols: map[string][]string{},
		literals: map[*ast.FuncLit]string{}, owners: map[*ast.FuncDecl]string{}, contexts: []row{},
		objects: map[types.Object]string{}, preambles: map[*ast.File]string{}, declarations: map[*ast.GenDecl][]row{}}
	units := []row{}
	valid := []*packages.Package{}
	for _, pkg := range pkgs {
		files, imports, errors := []string{}, []string{}, []string{}
		for _, filename := range pkg.CompiledGoFiles {
			path, relErr := filepath.Rel(root, filename)
			if relErr != nil || path == ".." || strings.HasPrefix(path, ".."+string(filepath.Separator)) {
				return nil, fmt.Errorf("package source outside snapshot")
			}
			files = append(files, filepath.ToSlash(path))
		}
		for name := range pkg.Imports {
			imports = append(imports, name)
		}
		for _, problem := range pkg.Errors {
			errors = append(errors, strings.ReplaceAll(problem.Error(), root, "<source>"))
		}
		sort.Strings(files)
		sort.Strings(imports)
		sort.Strings(errors)
		status := "parsed"
		if len(errors) != 0 || pkg.IllTyped || pkg.TypesInfo == nil {
			status = "failed"
		} else {
			valid = append(valid, pkg)
		}
		units = append(units, row{"path": pkg.PkgPath, "files": files, "imports": imports,
			"status": status, "errors": errors})
	}
	// Declaration references are evidence dependencies, never execution edges.
	for _, pkg := range valid {
		for _, file := range pkg.Syntax {
			end := file.Name.End()
			for _, decl := range file.Decls {
				if group, ok := decl.(*ast.GenDecl); ok && group.Tok == token.IMPORT {
					end = group.End()
				}
			}
			path, _ := e.location(pkg, file.Pos())
			_, position := e.location(pkg, end-1)
			id := identity("go-preamble", pkg.PkgPath, path)
			e.preambles[file] = id
			e.contexts = append(e.contexts, row{"id": id, "language": "go", "scope": pkg.PkgPath,
				"kind": "preamble", "name": path, "path": path, "line": 1,
				"end_line": position.Line, "references": []string{}})
			for _, decl := range file.Decls {
				group, ok := decl.(*ast.GenDecl)
				if !ok || group.Tok == token.IMPORT {
					continue
				}
				for _, spec := range group.Specs {
					var name, kind string
					switch value := spec.(type) {
					case *ast.TypeSpec:
						name, kind = value.Name.Name, "type"
					case *ast.ValueSpec:
						name, kind = value.Names[0].Name, "value"
					default:
						continue
					}
					id := e.context(pkg, group, name, kind, spec.Pos())
					e.declarations[group] = append(e.declarations[group], e.contexts[len(e.contexts)-1])
					ast.Inspect(spec, func(n ast.Node) bool {
						if ident, ok := n.(*ast.Ident); ok {
							if obj := pkg.TypesInfo.Defs[ident]; obj != nil {
								e.objects[obj] = id
							}
						}
						return true
					})
				}
			}
		}
	}
	for _, pkg := range valid {
		for _, file := range pkg.Syntax {
			for _, decl := range file.Decls {
				if group, ok := decl.(*ast.GenDecl); ok && group.Tok != token.IMPORT {
					refs := e.references(pkg, group, e.preambles[file])
					for _, context := range e.declarations[group] {
						context["references"] = refs
					}
				}
			}
		}
	}
	for _, pkg := range valid {
		for _, file := range pkg.Syntax {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				object, ok := pkg.TypesInfo.Defs[fn.Name].(*types.Func)
				if !ok {
					continue
				}
				sig, kind := object.Type().(*types.Signature), "function"
				key, name := symbol(object)
				if sig.Recv() != nil {
					kind = "method"
				}
				id := e.definition(pkg, fn, object.Name(), name, kind, sig)
				e.functions[len(e.functions)-1]["context_ids"] = e.references(pkg, fn, e.preambles[file])
				e.owners[fn] = id
				e.symbols[key] = append(e.symbols[key], id)
				ast.Inspect(fn.Body, func(node ast.Node) bool {
					if lit, ok := node.(*ast.FuncLit); ok {
						path, position := e.location(pkg, lit.Pos())
						name := fmt.Sprintf("<literal@%s:%d:%d>", path, position.Line, position.Column)
						e.literals[lit] = e.definition(pkg, lit, name, pkg.PkgPath+"."+name,
							"lambda", pkg.TypesInfo.TypeOf(lit).(*types.Signature))
						e.functions[len(e.functions)-1]["context_ids"] = e.references(pkg, lit, e.preambles[file])
					}
					return true
				})
			}
		}
	}
	for _, pkg := range valid {
		for _, file := range pkg.Syntax {
			for _, decl := range file.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && e.owners[fn] != "" {
					e.walk(pkg, fn.Body, e.owners[fn])
				}
			}
		}
	}
	return row{"functions": e.functions, "calls": e.calls, "contexts": e.contexts, "units": units,
		"context": row{"module": module.Module.Mod.Path, "goos": runtime.GOOS, "goarch": runtime.GOARCH,
			"tests": false, "cgo": false, "network": false}}, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: extractor MODULE_ROOT")
		os.Exit(1)
	}
	result, err := extract(os.Args[1])
	if err == nil {
		err = json.NewEncoder(os.Stdout).Encode(result)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
