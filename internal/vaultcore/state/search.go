package state

import (
	"slices"
	"strings"
)

type scoredSummary struct {
	summary CipherSummary
	score   int
}

func searchCiphers(ciphers map[string]*Cipher, query string, filter SearchFilter, isReadOnly func(*Cipher) bool) []CipherSummary {
	q := strings.ToLower(strings.TrimSpace(query))
	var matches []scoredSummary

	for _, c := range ciphers {
		if !matchesFilter(c, filter) {
			continue
		}
		summary := summarizeCipher(c)
		if isReadOnly != nil {
			summary.ReadOnly = isReadOnly(c)
		}
		if q == "" {
			matches = append(matches, scoredSummary{summary: summary, score: 0})
			continue
		}
		if score, ok := scoreCipher(c, summary, q); ok {
			matches = append(matches, scoredSummary{summary: summary, score: score})
		}
	}

	slices.SortFunc(matches, func(a, b scoredSummary) int {
		if a.score != b.score {
			return b.score - a.score
		}
		return strings.Compare(strings.ToLower(a.summary.Name), strings.ToLower(b.summary.Name))
	})

	out := make([]CipherSummary, len(matches))
	for i, m := range matches {
		out[i] = m.summary
	}
	return out
}

func matchesFilter(c *Cipher, filter SearchFilter) bool {
	isDeleted := c.DeletedDate != nil
	if filter.Category == FilterTrash {
		return isDeleted
	}
	if isDeleted {
		return false
	}
	isArchived := c.ArchivedDate != nil
	if filter.Category == FilterArchive {
		return isArchived
	}
	if isArchived {
		return false
	}

	if filter.Type != nil && c.Type != *filter.Type {
		return false
	}
	if filter.OrganizationID != "" && (c.OrganizationID == nil || *c.OrganizationID != filter.OrganizationID) {
		return false
	}
	if filter.CollectionID != "" && !slices.Contains(c.CollectionIDs, filter.CollectionID) {
		return false
	}
	if filter.FolderID != "" {
		return c.FolderID != nil && *c.FolderID == filter.FolderID
	}

	switch filter.Category {
	case FilterFavorites:
		return c.Favorite
	case FilterNoFolder:
		return c.FolderID == nil || *c.FolderID == ""
	default:
		return true
	}
}

func scoreCipher(c *Cipher, summary CipherSummary, q string) (int, bool) {
	best := 0
	matched := false

	check := func(field string, weight int) {
		if field == "" {
			return
		}
		s := matchScore(strings.ToLower(field), q)
		if s > 0 {
			total := s * weight
			if !matched || total > best {
				best = total
				matched = true
			}
		}
	}

	check(summary.Name, 10)
	check(summary.Subtitle, 6)
	if c.Login != nil {
		for _, u := range c.Login.URIs {
			check(u.URI, 5)
		}
	}
	check(c.Notes, 2)

	return best, matched
}

func matchScore(haystack, needle string) int {
	if haystack == needle {
		return 100
	}
	if strings.HasPrefix(haystack, needle) {
		return 80
	}
	if strings.Contains(haystack, needle) {
		return 60
	}
	if isSubsequence(haystack, needle) {
		return 30
	}
	return 0
}

func isSubsequence(haystack, needle string) bool {
	hi := 0
	for ni := 0; ni < len(needle); ni++ {
		idx := strings.IndexByte(haystack[hi:], needle[ni])
		if idx < 0 {
			return false
		}
		hi += idx + 1
	}
	return true
}
