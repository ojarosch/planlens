package engine

import "planlens/internal/diff"

func setDiffForTest(ch diff.AttributeChange) ([]string, []string, bool) {
	return diff.SetDiff(ch)
}
