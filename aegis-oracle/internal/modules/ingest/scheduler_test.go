package ingest

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestNVDDeltaURLEncodesUTCOffset(t *testing.T) {
	start := time.Date(2026, 9, 23, 16, 0, 0, 0, time.UTC)
	end := start.Add(3 * time.Hour)
	requestURL := nvdDeltaURL(start, end, 2000, 25)
	if !strings.Contains(requestURL, "%2B00%3A00") {
		t.Fatalf("UTC offset must be URL encoded: %s", requestURL)
	}
	parsed, err := url.Parse(requestURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if query.Get("lastModStartDate") != "2026-09-23T16:00:00.000+00:00" ||
		query.Get("lastModEndDate") != "2026-09-23T19:00:00.000+00:00" ||
		query.Get("resultsPerPage") != "2000" || query.Get("startIndex") != "25" {
		t.Fatalf("unexpected NVD delta query: %v", query)
	}
}
