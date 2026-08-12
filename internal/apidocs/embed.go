package apidocs

import (
	"embed"
	"fmt"
	"sort"
)

// files contains the documentation snapshot compiled into this binary.
//
//go:embed docs/*.md
var files embed.FS

type Version struct {
	Version     string `json:"version"`
	Status      string `json:"status"`
	ContentType string `json:"content_type"`
}

func List() []Version {
	versions := []Version{
		{
			Version:     "v1",
			Status:      "current",
			ContentType: "text/markdown",
		},
	}

	sort.Slice(
		versions,
		func(i, j int) bool {
			return versions[i].Version < versions[j].Version
		},
	)

	return versions
}

func Get(version string) (Version, string, error) {
	if version != "v1" {
		return Version{}, "", fmt.Errorf(
			"unsupported API documentation version %q",
			version,
		)
	}

	body, err := files.ReadFile("docs/v1.md")
	if err != nil {
		return Version{}, "", err
	}

	meta := Version{
		Version:     "v1",
		Status:      "current",
		ContentType: "text/markdown",
	}

	return meta, string(body), nil
}
