// template-coverage — Go template AST branch coverage helper (§7.4, §4.4.3).
//
// Reads JSON from stdin:
//
//	{"template": "...", "inputs": [{"key": "value"}, ...]}
//
// Parses the Go template, identifies branch nodes (if/range/with),
// rewrites the template with coverage probes, executes with each input,
// and reports which branches fired.
//
// Writes JSON to stdout:
//
//	{
//	  "total_branches": N,
//	  "covered_branches": M,
//	  "coverage_pct": P,
//	  "uncovered": [...]
//	}
//
// Build: go build -o bin/template-coverage .
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"text/template"
)

type Input struct {
	Template string                   `json:"template"`
	Inputs   []map[string]interface{} `json:"inputs"`
}

type BranchInfo struct {
	BranchID        string `json:"branch_id"`
	Template        string `json:"template"`
	Line            int    `json:"line"`
	NodeType        string `json:"node_type"`
	GuardExpression string `json:"guard_expression"`
}

type Output struct {
	TotalBranches   int          `json:"total_branches"`
	CoveredBranches int          `json:"covered_branches"`
	CoveragePct     float64      `json:"coverage_pct"`
	Uncovered       []BranchInfo `json:"uncovered"`
}

type branchDef struct {
	id        string
	line      int
	nodeType  string
	guardExpr string
	trueID    string
	falseID   string
}

// Marker prefix used in instrumented output to detect branch execution.
const probePrefix = "##XPTEST_COV##"

func main() {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fatal("reading stdin: %v", err)
	}

	var input Input
	if err := json.Unmarshal(data, &input); err != nil {
		fatal("parsing JSON input: %v", err)
	}

	if input.Template == "" {
		writeOutput(Output{CoveragePct: 100.0, Uncovered: []BranchInfo{}})
		return
	}

	// Scan the template source for branch constructs and instrument them.
	branches, instrumented := instrumentTemplate(input.Template)

	if len(branches) == 0 {
		writeOutput(Output{CoveragePct: 100.0, Uncovered: []BranchInfo{}})
		return
	}

	// Parse the instrumented template.
	tmpl, err := template.New("composition").
		Option("missingkey=zero").
		Parse(instrumented)
	if err != nil {
		// If instrumentation broke parsing, fall back to reporting 0% coverage.
		writeOutput(Output{
			TotalBranches:   len(branches) * 2,
			CoveredBranches: 0,
			CoveragePct:     0.0,
			Uncovered:       allUncovered(branches),
		})
		return
	}

	// Execute with each input and collect fired probes.
	fired := make(map[string]bool)
	for _, inp := range input.Inputs {
		var buf strings.Builder
		err := tmpl.Execute(&buf, inp)
		if err != nil {
			continue
		}
		output := buf.String()
		// Scan output for probe markers.
		for _, line := range strings.Split(output, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, probePrefix) {
				probeID := strings.TrimPrefix(line, probePrefix)
				fired[probeID] = true
			}
		}
	}

	// Build results: each branch has a true and false side.
	var allBranchIDs []BranchInfo
	for _, b := range branches {
		allBranchIDs = append(allBranchIDs, BranchInfo{
			BranchID:        b.trueID,
			Template:        "composition",
			Line:            b.line,
			NodeType:        b.nodeType,
			GuardExpression: b.guardExpr,
		})
		allBranchIDs = append(allBranchIDs, BranchInfo{
			BranchID:        b.falseID,
			Template:        "composition",
			Line:            b.line,
			NodeType:        b.nodeType,
			GuardExpression: "!" + b.guardExpr,
		})
	}

	total := len(allBranchIDs)
	covCount := 0
	var uncov []BranchInfo
	for _, bi := range allBranchIDs {
		if fired[bi.BranchID] {
			covCount++
		} else {
			uncov = append(uncov, bi)
		}
	}
	if uncov == nil {
		uncov = []BranchInfo{}
	}

	pct := 0.0
	if total > 0 {
		pct = float64(covCount) / float64(total) * 100.0
	}

	writeOutput(Output{
		TotalBranches:   total,
		CoveredBranches: covCount,
		CoveragePct:     pct,
		Uncovered:       uncov,
	})
}

// instrumentTemplate scans the template source for branch constructs
// (if/range/with) and injects probe markers into true and else branches.
// Works with both multi-line and single-line templates by splitting on
// template action boundaries ({{ and }}).
func instrumentTemplate(src string) ([]branchDef, string) {
	var branches []branchDef
	branchCounter := 0

	ifRe := regexp.MustCompile(`^-?\s*if\s+(.+?)\s*-?$`)
	rangeRe := regexp.MustCompile(`^-?\s*range\s+(.+?)\s*-?$`)
	withRe := regexp.MustCompile(`^-?\s*with\s+(.+?)\s*-?$`)
	elseRe := regexp.MustCompile(`^-?\s*else\s*-?$`)

	type stackEntry struct {
		branchIdx int
	}
	var stack []stackEntry

	// Compute line number from character position in source.
	lineAt := func(pos int) int {
		return strings.Count(src[:pos], "\n") + 1
	}

	var result strings.Builder
	cursor := 0

	for cursor < len(src) {
		// Find next {{ ... }}
		start := strings.Index(src[cursor:], "{{")
		if start < 0 {
			result.WriteString(src[cursor:])
			break
		}
		start += cursor
		end := strings.Index(src[start+2:], "}}")
		if end < 0 {
			result.WriteString(src[cursor:])
			break
		}
		end += start + 2 + 2 // position after }}

		// Write text before the action
		result.WriteString(src[cursor:start])

		action := src[start:end]
		inner := src[start+2 : end-2] // content between {{ and }}
		lineNum := lineAt(start)

		var match []string
		nodeType := ""
		if match = ifRe.FindStringSubmatch(inner); match != nil {
			nodeType = "if"
		} else if match = rangeRe.FindStringSubmatch(inner); match != nil {
			nodeType = "range"
		} else if match = withRe.FindStringSubmatch(inner); match != nil {
			nodeType = "with"
		}

		if nodeType != "" {
			guard := match[1]
			trueID := fmt.Sprintf("composition:%d:%s:true", lineNum, nodeType)
			falseID := fmt.Sprintf("composition:%d:%s:false", lineNum, nodeType)

			branches = append(branches, branchDef{
				id:        fmt.Sprintf("branch-%d", branchCounter),
				line:      lineNum,
				nodeType:  nodeType,
				guardExpr: guard,
				trueID:    trueID,
				falseID:   falseID,
			})

			result.WriteString(action)
			result.WriteString("\n" + probePrefix + trueID + "\n")
			stack = append(stack, stackEntry{branchIdx: branchCounter})
			branchCounter++
		} else if elseRe.MatchString(inner) && len(stack) > 0 {
			top := stack[len(stack)-1]
			b := branches[top.branchIdx]
			result.WriteString(action)
			result.WriteString("\n" + probePrefix + b.falseID + "\n")
		} else {
			// end or other action — pass through
			if strings.TrimSpace(inner) == "end" || strings.TrimSpace(inner) == "- end" ||
				strings.TrimSpace(inner) == "end -" || strings.TrimSpace(inner) == "- end -" {
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
			}
			result.WriteString(action)
		}

		cursor = end
	}

	return branches, result.String()
}

func allUncovered(branches []branchDef) []BranchInfo {
	var result []BranchInfo
	for _, b := range branches {
		result = append(result, BranchInfo{
			BranchID:        b.trueID,
			Template:        "composition",
			Line:            b.line,
			NodeType:        b.nodeType,
			GuardExpression: b.guardExpr,
		})
		result = append(result, BranchInfo{
			BranchID:        b.falseID,
			Template:        "composition",
			Line:            b.line,
			NodeType:        b.nodeType,
			GuardExpression: "!" + b.guardExpr,
		})
	}
	return result
}

func writeOutput(out Output) {
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		fatal("marshaling output: %v", err)
	}
	os.Stdout.Write(data)
	os.Stdout.Write([]byte("\n"))
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "template-coverage: "+format+"\n", args...)
	os.Exit(1)
}
