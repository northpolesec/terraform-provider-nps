// Copyright 2026 North Pole Security, Inc.
package provider

import "fmt"

const (
	listPageSize = 1000
	maxListPages = 10000
)

// pageHasMore treats the API's More field as a continuation hint rather than
// an authoritative termination signal. Some endpoints can return More=false
// for a full page, so a full page always causes one more request.
func pageHasMore(itemCount int, responseMore bool) bool {
	return responseMore || itemCount >= listPageSize
}

// collectPages walks a one-based Workshop pagination API. The fetch callback
// normalizes API-specific page and response types into a common shape. itemKey
// returns a stable, unique resource identity used to detect duplicates within
// a page and overlapping or repeated pages.
func collectPages[T any](
	fetch func(page int) (items []T, more bool, err error),
	itemKey func(T) string,
) ([]T, error) {
	var all []T
	seenItems := make(map[string]int)
	for page := 1; page <= maxListPages; page++ {
		items, more, err := fetch(page)
		if err != nil {
			return nil, err
		}
		if len(items) == 0 {
			if more {
				return nil, fmt.Errorf("pagination returned more=true with an empty page %d", page)
			}
			return all, nil
		}

		for _, item := range items {
			key := itemKey(item)
			if priorPage, ok := seenItems[key]; ok {
				return nil, fmt.Errorf("pagination returned a duplicate item identity on overlapping or repeated page %d; first seen on page %d", page, priorPage)
			}
			seenItems[key] = page
		}

		all = append(all, items...)
		if !pageHasMore(len(items), more) {
			return all, nil
		}
	}
	return nil, fmt.Errorf("pagination exceeded %d pages", maxListPages)
}
