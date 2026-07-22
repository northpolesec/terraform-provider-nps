// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

func intPageKey(value int) string {
	return strconv.Itoa(value)
}

func TestCollectPages(t *testing.T) {
	t.Parallel()

	pages := map[int][]int{1: {1, 2}, 2: {3}}
	got, err := collectPages(func(page int) ([]int, bool, error) {
		items := pages[page]
		return items, page == 1, nil
	}, intPageKey)
	if err != nil {
		t.Fatalf("collectPages returned an error: %v", err)
	}
	if want := []int{1, 2, 3}; !reflect.DeepEqual(got, want) {
		t.Fatalf("collectPages = %v, want %v", got, want)
	}
}

func TestCollectPagesContinuesAfterFullPageWithoutMore(t *testing.T) {
	t.Parallel()

	fullPage := make([]int, listPageSize)
	for i := range fullPage {
		fullPage[i] = i
	}

	var pages []int
	got, err := collectPages(func(page int) ([]int, bool, error) {
		pages = append(pages, page)
		switch page {
		case 1:
			return fullPage, false, nil
		case 2:
			return []int{listPageSize}, false, nil
		default:
			t.Fatalf("unexpected page %d", page)
			return nil, false, nil
		}
	}, intPageKey)
	if err != nil {
		t.Fatalf("collectPages returned an error: %v", err)
	}
	if want := []int{1, 2}; !reflect.DeepEqual(pages, want) {
		t.Fatalf("requested pages = %v, want %v", pages, want)
	}
	if len(got) != listPageSize+1 || got[len(got)-1] != listPageSize {
		t.Fatalf("collected %d items with final item %d, want %d items ending in %d", len(got), got[len(got)-1], listPageSize+1, listPageSize)
	}
}

func TestCollectPagesExactFullFinalPageMakesOneExtraRequest(t *testing.T) {
	t.Parallel()

	fullPage := make([]int, listPageSize)
	for i := range fullPage {
		fullPage[i] = i
	}

	calls := 0
	got, err := collectPages(func(page int) ([]int, bool, error) {
		calls++
		if page == 1 {
			return fullPage, false, nil
		}
		return nil, false, nil
	}, intPageKey)
	if err != nil {
		t.Fatalf("collectPages returned an error: %v", err)
	}
	if calls != 2 {
		t.Fatalf("fetch calls = %d, want 2", calls)
	}
	if !reflect.DeepEqual(got, fullPage) {
		t.Fatalf("collectPages returned %d items, want the %d-item full page", len(got), len(fullPage))
	}
}

func TestCollectPagesRejectsRepeatedPage(t *testing.T) {
	t.Parallel()

	calls := 0
	_, err := collectPages(func(page int) ([]int, bool, error) {
		calls++
		return []int{42}, true, nil
	}, intPageKey)
	if err == nil || !strings.Contains(err.Error(), "repeated") {
		t.Fatalf("collectPages error = %v, want repeated-page error", err)
	}
	if calls != 2 {
		t.Fatalf("fetch calls = %d, want 2", calls)
	}
}

func TestCollectPagesRejectsPartiallyOverlappingPages(t *testing.T) {
	t.Parallel()

	calls := 0
	_, err := collectPages(func(page int) ([]int, bool, error) {
		calls++
		if page == 1 {
			return []int{1, 2}, true, nil
		}
		return []int{2, 3}, false, nil
	}, intPageKey)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("collectPages error = %v, want duplicate-identity error", err)
	}
	if calls != 2 {
		t.Fatalf("fetch calls = %d, want 2", calls)
	}
}

func TestCollectPagesRejectsDuplicateIdentityWithinPage(t *testing.T) {
	t.Parallel()

	_, err := collectPages(func(page int) ([]int, bool, error) {
		return []int{1, 1}, false, nil
	}, intPageKey)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("collectPages error = %v, want duplicate-identity error", err)
	}
}

func TestCollectPagesRejectsEmptyContinuation(t *testing.T) {
	t.Parallel()

	_, err := collectPages(func(page int) ([]int, bool, error) {
		return nil, true, nil
	}, intPageKey)
	if err == nil {
		t.Fatal("expected an error for more=true with an empty page")
	}
}

func TestCollectPagesReturnsFetchError(t *testing.T) {
	t.Parallel()

	want := errors.New("boom")
	_, err := collectPages(func(page int) ([]int, bool, error) {
		return nil, false, want
	}, intPageKey)
	if !errors.Is(err, want) {
		t.Fatalf("collectPages error = %v, want %v", err, want)
	}
}

func TestListTagsPageUsesResponseMoreWithFullPageFallback(t *testing.T) {
	t.Parallel()

	shortPage := apipb.ListTagsResponse_builder{
		Tags: []*apipb.TagStats{{}},
		More: proto.Bool(true),
	}.Build()
	tags, more := listTagsPage(shortPage)
	if len(tags) != 1 || !more {
		t.Fatalf("short tag page: len=%d more=%v, want len=1 more=true", len(tags), more)
	}

	fullFinalPage := apipb.ListTagsResponse_builder{
		Tags: make([]*apipb.TagStats, listPageSize),
		More: proto.Bool(false),
	}.Build()
	_, more = listTagsPage(fullFinalPage)
	if !more {
		t.Fatal("full tag page reported more=false; a full page must probe for a following page")
	}
}

func TestCollectTagPagesContinuesAfterFullPageWithoutMore(t *testing.T) {
	t.Parallel()

	fullPage := make([]*apipb.TagStats, listPageSize)
	for i := range fullPage {
		fullPage[i] = apipb.TagStats_builder{Tag: "tag-" + strconv.Itoa(i)}.Build()
	}

	responses := map[int]*apipb.ListTagsResponse{
		1: apipb.ListTagsResponse_builder{
			Tags: fullPage,
			More: proto.Bool(false),
		}.Build(),
		2: apipb.ListTagsResponse_builder{
			Tags: []*apipb.TagStats{apipb.TagStats_builder{Tag: "tag-final"}.Build()},
			More: proto.Bool(false),
		}.Build(),
	}

	var pages []int
	tags, err := collectPages(func(page int) ([]*apipb.TagStats, bool, error) {
		pages = append(pages, page)
		items, more := listTagsPage(responses[page])
		return items, more, nil
	}, func(tag *apipb.TagStats) string {
		return tag.GetTag()
	})
	if err != nil {
		t.Fatalf("collectPages returned an error: %v", err)
	}
	if want := []int{1, 2}; !reflect.DeepEqual(pages, want) {
		t.Fatalf("requested pages = %v, want %v", pages, want)
	}
	if len(tags) != listPageSize+1 || tags[len(tags)-1].GetTag() != "tag-final" {
		t.Fatalf("collected %d tags with final tag %q, want %d tags ending in tag-final", len(tags), tags[len(tags)-1].GetTag(), listPageSize+1)
	}
}

func TestListGroupsPageUsesResponseMoreWithFullPageFallback(t *testing.T) {
	t.Parallel()

	shortPage := apipb.ListGroupsResponse_builder{
		Groups: []*apipb.Group{{}},
		More:   proto.Bool(true),
	}.Build()
	groups, more := listGroupsPage(shortPage)
	if len(groups) != 1 || !more {
		t.Fatalf("short group page: len=%d more=%v, want len=1 more=true", len(groups), more)
	}

	fullFinalPage := apipb.ListGroupsResponse_builder{
		Groups: make([]*apipb.Group, listPageSize),
		More:   proto.Bool(false),
	}.Build()
	_, more = listGroupsPage(fullFinalPage)
	if !more {
		t.Fatal("full group page reported more=false; a full page must probe for a following page")
	}
}

func TestListAPIKeysPageUsesLengthBecauseResponseHasNoMore(t *testing.T) {
	t.Parallel()

	fields := (&apipb.ListAPIKeysResponse{}).ProtoReflect().Descriptor().Fields()
	if fields.ByName("more") != nil {
		t.Fatal("ListAPIKeysResponse now has a More field; use it instead of page length")
	}

	tests := []struct {
		name  string
		count int
		more  bool
	}{
		{name: "empty final page", count: 0, more: false},
		{name: "short final page", count: listPageSize - 1, more: false},
		{name: "full page may continue", count: listPageSize, more: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys, more := listAPIKeysPage(apipb.ListAPIKeysResponse_builder{
				Keys: make([]*apipb.APIKey, tt.count),
			}.Build())
			if len(keys) != tt.count || more != tt.more {
				t.Fatalf("len=%d more=%v, want len=%d more=%v", len(keys), more, tt.count, tt.more)
			}
		})
	}
}

func TestCollectAPIKeyPagesRejectsRepeatedFullPage(t *testing.T) {
	t.Parallel()

	fullPage := make([]*apipb.APIKey, listPageSize)
	for i := range fullPage {
		fullPage[i] = apipb.APIKey_builder{Name: "key-" + strconv.Itoa(i)}.Build()
	}

	calls := 0
	_, err := collectPages(func(page int) ([]*apipb.APIKey, bool, error) {
		calls++
		keys, more := listAPIKeysPage(apipb.ListAPIKeysResponse_builder{Keys: fullPage}.Build())
		return keys, more, nil
	}, func(key *apipb.APIKey) string {
		return key.GetName()
	})
	if err == nil || !strings.Contains(err.Error(), "repeated") {
		t.Fatalf("collectPages error = %v, want repeated-page error", err)
	}
	if calls != 2 {
		t.Fatalf("fetch calls = %d, want 2", calls)
	}
}
