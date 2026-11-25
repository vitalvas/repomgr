package rpmrepo

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"path"
	"strings"
	"time"

	"go.vitalvas.com/repomgr/internal/pgpsign"
	"go.vitalvas.com/repomgr/internal/rpmfile"
)

const (
	nsCommon    string = "http://linux.duke.edu/metadata/common"
	nsRPM       string = "http://linux.duke.edu/metadata/rpm"
	nsFilelists string = "http://linux.duke.edu/metadata/filelists"
	nsOther     string = "http://linux.duke.edu/metadata/other"
	nsRepo      string = "http://linux.duke.edu/metadata/repo"

	msgAdded   string = "added"
	msgCreated string = "created"
	msgUpdated string = "updated"
)

type repoPackage struct {
	pkg rpmfile.Package
	// path is the pool file path relative to public/, starting with pool/.
	path  string
	mtime int64
}

// outputFile is one file of a repodata directory, in write order.
type outputFile struct {
	name string
	data []byte
	msg  string
}

type xmlVersion struct {
	Epoch uint32 `xml:"epoch,attr"`
	Ver   string `xml:"ver,attr"`
	Rel   string `xml:"rel,attr"`
}

type xmlChecksum struct {
	Type  string `xml:"type,attr"`
	PkgID string `xml:"pkgid,attr,omitempty"`
	Value string `xml:",chardata"`
}

type xmlLocation struct {
	Href string `xml:"href,attr"`
}

// The rpm: prefix is written as a literal name: encoding/xml would otherwise
// invent its own prefix, and the files must carry the conventional one.
type primaryMetadata struct {
	XMLName      xml.Name         `xml:"metadata"`
	Namespace    string           `xml:"xmlns,attr"`
	RPMNamespace string           `xml:"xmlns:rpm,attr"`
	Packages     int              `xml:"packages,attr"`
	Package      []primaryPackage `xml:"package"`
}

type primaryPackage struct {
	Type        string        `xml:"type,attr"`
	Name        string        `xml:"name"`
	Arch        string        `xml:"arch"`
	Version     xmlVersion    `xml:"version"`
	Checksum    xmlChecksum   `xml:"checksum"`
	Summary     string        `xml:"summary"`
	Description string        `xml:"description"`
	Packager    string        `xml:"packager"`
	URL         string        `xml:"url"`
	Time        primaryTime   `xml:"time"`
	Size        primarySize   `xml:"size"`
	Location    xmlLocation   `xml:"location"`
	Format      primaryFormat `xml:"format"`
}

type primaryTime struct {
	File  int64 `xml:"file,attr"`
	Build int64 `xml:"build,attr"`
}

type primarySize struct {
	Package   int64 `xml:"package,attr"`
	Installed int64 `xml:"installed,attr"`
	Archive   int64 `xml:"archive,attr"`
}

type primaryFormat struct {
	License     string      `xml:"rpm:license"`
	Vendor      string      `xml:"rpm:vendor"`
	Group       string      `xml:"rpm:group"`
	BuildHost   string      `xml:"rpm:buildhost"`
	SourceRPM   string      `xml:"rpm:sourcerpm"`
	HeaderRange headerRange `xml:"rpm:header-range"`
	Provides    *xmlDeps    `xml:"rpm:provides"`
	Requires    *xmlDeps    `xml:"rpm:requires"`
	Conflicts   *xmlDeps    `xml:"rpm:conflicts"`
	Obsoletes   *xmlDeps    `xml:"rpm:obsoletes"`
	Suggests    *xmlDeps    `xml:"rpm:suggests"`
	Enhances    *xmlDeps    `xml:"rpm:enhances"`
	Recommends  *xmlDeps    `xml:"rpm:recommends"`
	Supplements *xmlDeps    `xml:"rpm:supplements"`
	Files       []xmlFile   `xml:"file"`
}

type xmlFile struct {
	Type string `xml:"type,attr,omitempty"`
	Path string `xml:",chardata"`
}

type xmlDeps struct {
	Entries []xmlEntry `xml:"rpm:entry"`
}

type xmlEntry struct {
	Name  string `xml:"name,attr"`
	Flags string `xml:"flags,attr,omitempty"`
	// Epoch, Ver, and Rel are set when the raw value is not empty, so a value
	// that conversion empties is still written, as an empty attribute.
	Epoch *string `xml:"epoch,attr,omitempty"`
	Ver   *string `xml:"ver,attr,omitempty"`
	Rel   *string `xml:"rel,attr,omitempty"`
	Pre   string  `xml:"pre,attr,omitempty"`
}

type headerRange struct {
	Start int64 `xml:"start,attr"`
	End   int64 `xml:"end,attr"`
}

// listMetadata is the root of filelists.xml and other.xml; XMLName carries the
// root element name.
type listMetadata struct {
	XMLName   xml.Name
	Namespace string        `xml:"xmlns,attr"`
	Packages  int           `xml:"packages,attr"`
	Package   []listPackage `xml:"package"`
}

type listPackage struct {
	PkgID     string         `xml:"pkgid,attr"`
	Name      string         `xml:"name,attr"`
	Arch      string         `xml:"arch,attr"`
	Version   xmlVersion     `xml:"version"`
	Files     []xmlFile      `xml:"file"`
	Changelog []xmlChangelog `xml:"changelog"`
}

type xmlChangelog struct {
	Author string `xml:"author,attr"`
	Date   int64  `xml:"date,attr"`
	Text   string `xml:",chardata"`
}

type repomd struct {
	XMLName      xml.Name     `xml:"repomd"`
	Namespace    string       `xml:"xmlns,attr"`
	RPMNamespace string       `xml:"xmlns:rpm,attr"`
	Revision     int64        `xml:"revision"`
	Data         []repomdData `xml:"data"`
}

type repomdData struct {
	Type         string      `xml:"type,attr"`
	Checksum     xmlChecksum `xml:"checksum"`
	OpenChecksum xmlChecksum `xml:"open-checksum"`
	Location     xmlLocation `xml:"location"`
	Timestamp    int64       `xml:"timestamp"`
	Size         int         `xml:"size"`
	OpenSize     int         `xml:"open-size"`
}

func newVersion(p rpmfile.Package, c *textConv) xmlVersion {
	v := xmlVersion{Ver: c.value(p.Version, "VERSION"), Rel: c.value(p.Release, "RELEASE")}
	if p.Epoch != nil {
		v.Epoch = *p.Epoch
	}

	return v
}

// newDeps returns nil for an empty list. Entries with an empty name are
// skipped, so a list of only empty names gives an empty container.
func newDeps(list string, deps []dep, requires bool, c *textConv) *xmlDeps {
	if len(deps) == 0 {
		return nil
	}

	var out xmlDeps

	for _, d := range deps {
		if d.name == "" {
			continue
		}

		e := xmlEntry{Name: c.value(d.name, depField, list, d.name)}

		if d.flags != "" {
			e.Flags = d.flags

			for _, a := range []struct {
				raw string
				dst **string
			}{{d.epoch, &e.Epoch}, {d.ver, &e.Ver}, {d.rel, &e.Rel}} {
				if a.raw != "" {
					v := c.value(a.raw, depField, list, d.name)
					*a.dst = &v
				}
			}
		}

		if requires && d.pre {
			e.Pre = "1"
		}

		out.Entries = append(out.Entries, e)
	}

	return &out
}

// inPrimary is the rule for which files primary.xml lists.
func inPrimary(p string) bool {
	return strings.HasPrefix(p, "/etc/") || strings.Contains(p, "bin/") || p == "/usr/lib/sendmail"
}

// newFiles returns the files of a package, only those primary.xml lists when
// primary is set.
func newFiles(files []rpmfile.File, primary bool, c *textConv) []xmlFile {
	var out []xmlFile

	for i, f := range files {
		if primary && !inPrimary(f.Path) {
			continue
		}

		x := xmlFile{Path: c.value(f.Path, "file %d", i)}

		switch {
		case f.IsDir():
			x.Type = "dir"
		case f.IsGhost():
			x.Type = "ghost"
		}

		out = append(out, x)
	}

	return out
}

func marshalXML(v any) ([]byte, error) {
	data, err := xml.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}

	return fmt.Appendf(nil, "%s%s\n", xml.Header, data), nil
}

func renderPrimary(pkgs []repoPackage) ([]byte, error) {
	md := primaryMetadata{
		Namespace:    nsCommon,
		RPMNamespace: nsRPM,
		Packages:     len(pkgs),
	}

	for _, p := range pkgs {
		pp, err := newPrimaryPackage(p)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p.path, err)
		}

		md.Package = append(md.Package, pp)
	}

	return marshalXML(md)
}

// newPrimaryPackage converts every text value with textValue, after the
// dependency filtering, which compares the header strings.
func newPrimaryPackage(p repoPackage) (primaryPackage, error) {
	var c textConv

	deps := buildDeps(p.pkg)

	pp := primaryPackage{
		Type:        "rpm",
		Name:        c.value(p.pkg.Name, "NAME"),
		Arch:        c.value(p.pkg.Arch, "ARCH"),
		Version:     newVersion(p.pkg, &c),
		Checksum:    xmlChecksum{Type: "sha256", PkgID: "YES", Value: p.pkg.SHA256},
		Summary:     c.value(p.pkg.Summary, "SUMMARY"),
		Description: c.value(p.pkg.Description, "DESCRIPTION"),
		Packager:    c.value(p.pkg.Packager, "PACKAGER"),
		URL:         c.value(p.pkg.URL, "URL"),
		Time:        primaryTime{File: p.mtime, Build: int64(p.pkg.BuildTime)},
		// The reference writer keeps sizes in a gint64 and prints them signed.
		Size: primarySize{Package: p.pkg.Size, Installed: int64(p.pkg.InstalledSize), Archive: int64(p.pkg.ArchiveSize)},
		// The repository directory is public/<basearch>/<release>/<component>/.
		Location: xmlLocation{Href: c.value(fmt.Sprintf("../../../%s", p.path), "location")},
		Format: primaryFormat{
			License:     c.value(p.pkg.License, "LICENSE"),
			Vendor:      c.value(p.pkg.Vendor, "VENDOR"),
			Group:       c.value(p.pkg.Group, "GROUP"),
			BuildHost:   c.value(p.pkg.BuildHost, "BUILDHOST"),
			SourceRPM:   c.value(p.pkg.SourceRPM, "SOURCERPM"),
			HeaderRange: headerRange{Start: p.pkg.HeaderStart, End: p.pkg.HeaderEnd},
			Provides:    newDeps("provides", deps.provides, false, &c),
			Requires:    newDeps("requires", deps.requires, true, &c),
			Conflicts:   newDeps("conflicts", deps.conflicts, false, &c),
			Obsoletes:   newDeps("obsoletes", deps.obsoletes, false, &c),
			Recommends:  newDeps("recommends", deps.recommends, false, &c),
			Suggests:    newDeps("suggests", deps.suggests, false, &c),
			Supplements: newDeps("supplements", deps.supplements, false, &c),
			Enhances:    newDeps("enhances", deps.enhances, false, &c),
			Files:       newFiles(p.pkg.Files, true, &c),
		},
	}

	return pp, c.err
}

// renderList writes the package files when withFiles is set (filelists), and
// the kept changelog entries otherwise (other).
func renderList(root, ns string, pkgs []repoPackage, withFiles bool) ([]byte, error) {
	md := listMetadata{
		XMLName:   xml.Name{Local: root},
		Namespace: ns,
		Packages:  len(pkgs),
	}

	for _, p := range pkgs {
		lp, err := newListPackage(p, withFiles)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p.path, err)
		}

		md.Package = append(md.Package, lp)
	}

	return marshalXML(md)
}

func newListPackage(p repoPackage, withFiles bool) (listPackage, error) {
	var c textConv

	lp := listPackage{
		PkgID:   p.pkg.SHA256,
		Name:    c.value(p.pkg.Name, "NAME"),
		Arch:    c.value(p.pkg.Arch, "ARCH"),
		Version: newVersion(p.pkg, &c),
	}

	if withFiles {
		lp.Files = newFiles(p.pkg.Files, false, &c)

		return lp, c.err
	}

	lp.Changelog = keptChangelog(p.pkg.Changelog)

	// Entries are in output order, the reverse of header order.
	for i := range lp.Changelog {
		e := &lp.Changelog[i]
		n := len(lp.Changelog) - 1 - i
		e.Author = c.value(e.Author, "changelog entry %d author", n)
		e.Text = c.value(e.Text, "changelog entry %d text", n)
	}

	return lp, c.err
}

// gzipBytes leaves the gzip header name and time empty, so equal content gives
// equal bytes and equal file names.
func gzipBytes(data []byte) ([]byte, error) {
	var buf bytes.Buffer

	w, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}

	_, err = w.Write(data)
	if err != nil {
		return nil, err
	}

	err = w.Close()
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func hexSHA256(data []byte) string {
	sum := sha256.Sum256(data)

	return hex.EncodeToString(sum[:])
}

// renderRepo returns the files of one repodata directory: the three metadata
// files, then repomd.xml.asc, then repomd.xml.
func renderRepo(pkgs []repoPackage, privateKey []byte, now time.Time) (repomd, []outputFile, error) {
	primary, err := renderPrimary(pkgs)
	if err != nil {
		return repomd{}, nil, fmt.Errorf("render primary.xml: %w", err)
	}

	filelists, err := renderList("filelists", nsFilelists, pkgs, true)
	if err != nil {
		return repomd{}, nil, fmt.Errorf("render filelists.xml: %w", err)
	}

	other, err := renderList("otherdata", nsOther, pkgs, false)
	if err != nil {
		return repomd{}, nil, fmt.Errorf("render other.xml: %w", err)
	}

	md := repomd{
		Namespace:    nsRepo,
		RPMNamespace: nsRPM,
		Revision:     now.Unix(),
	}

	var files []outputFile

	for _, m := range []struct {
		typ  string
		data []byte
	}{
		{"primary", primary},
		{"filelists", filelists},
		{"other", other},
	} {
		gz, err := gzipBytes(m.data)
		if err != nil {
			return repomd{}, nil, fmt.Errorf("compress %s.xml: %w", m.typ, err)
		}

		sum := hexSHA256(gz)
		name := fmt.Sprintf("%s-%s.xml.gz", sum, m.typ)

		md.Data = append(md.Data, repomdData{
			Type:         m.typ,
			Checksum:     xmlChecksum{Type: "sha256", Value: sum},
			OpenChecksum: xmlChecksum{Type: "sha256", Value: hexSHA256(m.data)},
			Location:     xmlLocation{Href: path.Join("repodata", name)},
			Timestamp:    now.Unix(),
			Size:         len(gz),
			OpenSize:     len(m.data),
		})

		files = append(files, outputFile{name: name, data: gz, msg: msgAdded})
	}

	data, err := marshalXML(md)
	if err != nil {
		return repomd{}, nil, fmt.Errorf("render repomd.xml: %w", err)
	}

	signed, err := pgpsign.Sign(privateKey, data)
	if err != nil {
		return repomd{}, nil, fmt.Errorf("sign repomd.xml: %w", err)
	}

	return md, append(files,
		outputFile{name: "repomd.xml.asc", data: signed.Detached, msg: msgUpdated},
		outputFile{name: "repomd.xml", data: data, msg: msgUpdated},
	), nil
}
