package normalise

import (
	"strings"
	"testing"
)

// image-reference decomposition tests (ARCH-003 §2 item 5): references of
// the form [registry/]repository[:tag][@digest] decompose and round-trip;
// malformed references are positioned *SyntaxError values. No defaulting
// (docker.io is never invented) and no case folding.

const testDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestParseImageRefValid(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want ImageRef
	}{
		{"bare name", "nginx", ImageRef{Repository: "nginx"}},
		{"name and tag", "nginx:1.25", ImageRef{Repository: "nginx", Tag: "1.25"}},
		{"namespace path", "library/nginx:1.25", ImageRef{Repository: "library/nginx", Tag: "1.25"}},
		{"registry and namespace", "docker.io/library/nginx:1.25", ImageRef{Registry: "docker.io", Repository: "library/nginx", Tag: "1.25"}},
		{"registry with port", "localhost:5000/nginx", ImageRef{Registry: "localhost:5000", Repository: "nginx"}},
		{"localhost registry", "localhost/nginx", ImageRef{Registry: "localhost", Repository: "nginx"}},
		{"digest only", "nginx@" + testDigest, ImageRef{Repository: "nginx", Digest: testDigest}},
		{"tag and digest", "registry.example.com/team/app:v2.1.0@" + testDigest, ImageRef{Registry: "registry.example.com", Repository: "team/app", Tag: "v2.1.0", Digest: testDigest}},
		{"tag charset", "myrepo/my-app:1.25-alpine.1", ImageRef{Repository: "myrepo/my-app", Tag: "1.25-alpine.1"}},
		{"repository separators", "team_repo/team_app/my-app", ImageRef{Repository: "team_repo/team_app/my-app"}},
	}
	for _, tc := range cases {
		got, err := ParseImageRef(tc.in)
		if err != nil {
			t.Errorf("%s: ParseImageRef(%q): unexpected error: %v", tc.name, tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: ParseImageRef(%q) = %+v, want %+v", tc.name, tc.in, got, tc.want)
		}
		if got.String() != tc.in {
			t.Errorf("%s: round-trip failed: ParseImageRef(%q).String() = %q", tc.name, tc.in, got.String())
		}
	}
}

func TestParseImageRefMalformed(t *testing.T) {
	longTag := strings.Repeat("a", 129)
	cases := []struct {
		name  string
		in    string
		field string
	}{
		{"empty", "", ""},
		{"digest without repository", "@" + testDigest, ""},
		{"empty digest", "nginx@", "digest"},
		{"bad digest algorithm", "nginx@SHA256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "digest"},
		{"uppercase digest hex", "nginx@sha256:ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEF", "digest"},
		{"short digest hex", "nginx@sha256:abcdef", "digest"},
		{"empty tag", "nginx:", "tag"},
		{"tag too long", "nginx:" + longTag, "tag"},
		{"tag starts with hyphen", "nginx:-latest", "tag"},
		{"uppercase repository", "Nginx", "repository"},
		{"uppercase namespace", "team/Nginx:1.0", "repository"},
		{"empty repository component", "team//app:1.0", "repository"},
		{"repository with colon beyond tag", "nginx:1.25:extra", "repository"},
		{"space in repository", "team/my app:1.0", "repository"},
		{"bad registry", "exa mple.com/nginx", "registry"},
	}
	for _, tc := range cases {
		_, err := ParseImageRef(tc.in)
		assertSyntaxError(t, err, "image", tc.field, 0, tc.in)
	}
}

// TestParseImageRefNoDefaulting pins the decomposition contract: an
// explicit registry is only recognised by the docker grammar (first
// component contains '.' or ':', or is "localhost"); a bare name or
// namespace path never invents docker.io.
func TestParseImageRefNoDefaulting(t *testing.T) {
	for _, in := range []string{"ubuntu", "library/ubuntu", "k8s.gcr.io/ingress-nginx/controller"} {
		got, err := ParseImageRef(in)
		if err != nil {
			t.Fatalf("ParseImageRef(%q): %v", in, err)
		}
		if strings.Contains(got.String(), "docker.io") {
			t.Errorf("ParseImageRef(%q) must not invent docker.io, got %q", in, got.String())
		}
	}
	r, err := ParseImageRef("k8s.gcr.io/ingress-nginx/controller")
	if err != nil {
		t.Fatal(err)
	}
	if r.Registry != "k8s.gcr.io" || r.Repository != "ingress-nginx/controller" {
		t.Errorf("registry split wrong: %+v", r)
	}
}
