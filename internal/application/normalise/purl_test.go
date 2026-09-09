package normalise

import "testing"

// purl decomposition tests (ARCH-003 §2 item 4): valid package URLs
// decompose into type/namespace/name/version (+ raw qualifiers/subpath)
// and round-trip; malformed purls are positioned *SyntaxError values.

func TestParsePURLValid(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want PURL
	}{
		{
			name: "deb with version",
			in:   "pkg:deb/debian/curl@7.0.0-1",
			want: PURL{Type: "deb", Namespace: "debian", Name: "curl", Version: "7.0.0-1"},
		},
		{
			name: "golang deep namespace",
			in:   "pkg:golang/github.com/gorilla/mux@v1.8.0",
			want: PURL{Type: "golang", Namespace: "github.com/gorilla", Name: "mux", Version: "v1.8.0"},
		},
		{
			name: "maven dotted namespace",
			in:   "pkg:maven/org.apache.commons/commons-lang3@3.4",
			want: PURL{Type: "maven", Namespace: "org.apache.commons", Name: "commons-lang3", Version: "3.4"},
		},
		{
			name: "npm no namespace",
			in:   "pkg:npm/express@4.18.2",
			want: PURL{Type: "npm", Name: "express", Version: "4.18.2"},
		},
		{
			name: "no version no namespace",
			in:   "pkg:pypi/django",
			want: PURL{Type: "pypi", Name: "django"},
		},
		{
			name: "case preserved in name",
			in:   "pkg:nuget/Newtonsoft.Json@13.0.1",
			want: PURL{Type: "nuget", Name: "Newtonsoft.Json", Version: "13.0.1"},
		},
		{
			name: "qualifiers kept raw",
			in:   "pkg:maven/org.acme/foo@1.0?type=jar&classifier=sources",
			want: PURL{Type: "maven", Namespace: "org.acme", Name: "foo", Version: "1.0", Qualifiers: "type=jar&classifier=sources"},
		},
		{
			name: "subpath kept raw",
			in:   "pkg:github/octocat/hello-world#readme.md",
			want: PURL{Type: "github", Namespace: "octocat", Name: "hello-world", Subpath: "readme.md"},
		},
		{
			name: "version with colon (digest)",
			in:   "pkg:oci/nginx@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: PURL{Type: "oci", Name: "nginx", Version: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		},
		{
			name: "version with tilde and plus",
			in:   "pkg:deb/debian/curl@7.0.0~rc1+dfsg-1",
			want: PURL{Type: "deb", Namespace: "debian", Name: "curl", Version: "7.0.0~rc1+dfsg-1"},
		},
		{
			name: "percent-encoded name kept encoded",
			in:   "pkg:npm/%40angular/core@12.0.0",
			want: PURL{Type: "npm", Namespace: "%40angular", Name: "core", Version: "12.0.0"},
		},
	}
	for _, tc := range cases {
		got, err := ParsePURL(tc.in)
		if err != nil {
			t.Errorf("%s: ParsePURL(%q): unexpected error: %v", tc.name, tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: ParsePURL(%q) = %+v, want %+v", tc.name, tc.in, got, tc.want)
		}
		if got.String() != tc.in {
			t.Errorf("%s: round-trip failed: ParsePURL(%q).String() = %q", tc.name, tc.in, got.String())
		}
	}
}

func TestParsePURLMalformed(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		field string
	}{
		{"empty", "", ""},
		{"bad scheme", "PKG:deb/debian/curl@7.0", ""},
		{"missing scheme", "deb/debian/curl@7.0", ""},
		{"type only no slash", "pkg:deb", "type"},
		{"uppercase type", "pkg:Deb/debian/curl@7.0", "type"},
		{"type with underscore", "pkg:de_b/curl@7.0", "type"},
		{"missing name", "pkg:deb/", "name"},
		{"empty name segment", "pkg:deb/debian/", "name"},
		{"empty namespace segment", "pkg:deb//curl@7.0", "namespace"},
		{"empty inner namespace segment", "pkg:deb/a//b@7.0", "namespace"},
		{"empty version", "pkg:deb/debian/curl@", "version"},
		{"empty qualifiers", "pkg:deb/debian/curl@7.0?", "qualifiers"},
		{"empty subpath", "pkg:deb/debian/curl@7.0#", "subpath"},
		{"whitespace in name", "pkg:npm/ex press@1.0", "name"},
		{"whitespace in version", "pkg:npm/express@1 .0", "version"},
		{"bad percent escape in name", "pkg:npm/foo%zz@1.0", "name"},
		{"qualifier pair without equals", "pkg:deb/debian/curl@7.0?arch", "qualifiers"},
		{"qualifier with empty key", "pkg:deb/debian/curl@7.0?=amd64", "qualifiers"},
	}
	for _, tc := range cases {
		_, err := ParsePURL(tc.in)
		assertSyntaxError(t, err, "purl", tc.field, 0, tc.in)
	}
}

// TestParsePURLTypeCharset pins the accepted type charset: lowercase
// letters/digits with '.', '+' and '-' inside.
func TestParsePURLTypeCharset(t *testing.T) {
	for _, typ := range []string{"deb", "rpm", "npm", "golang", "maven", "pypi", "github", "generic", "a.b+c-d"} {
		if _, err := ParsePURL("pkg:" + typ + "/name@1.0"); err != nil {
			t.Errorf("type %q must parse, got %v", typ, err)
		}
	}
	for _, typ := range []string{"Deb", "de_b", "1deb", "", "de b", "de:b"} {
		if _, err := ParsePURL("pkg:" + typ + "/name@1.0"); err == nil {
			t.Errorf("type %q must be rejected", typ)
		}
	}
}
