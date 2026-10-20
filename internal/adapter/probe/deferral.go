package probe

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/donislawdev/certdoctor/internal/core/report"
)

// This file is where curl and git on Linux hand their answer to the platform's
// own store - ADR110, decided by the owner 2026-10-20 after probe S26 - and so
// does node from a distribution's package, ADR111 part 6, after probe S27.
//
// A BUILD THAT NAMES NO CA FILE READS THE ONE IT WAS COMPILED WITH, and nothing
// on disk says which that is. What can be said is narrower and checkable: the
// binary came from the distribution's own package, the distribution builds the
// library it reads through - libcurl, or OpenSSL itself - to read a known file,
// and that file is the one the platform store's row judged. When all of that holds the two rows are one store, and the row
// names the other instead of judging the same file a second time - the shape
// curl on Schannel took in ADR108 part 4.
//
// EVERY CONDITION THAT DOES NOT HOLD IS SAID ON ITS OWN, never folded into one
// shared "unknown" - a person who reads which one failed knows what to look at.

// Ports are the three ways a probe reads this machine, handed over as the plain
// functions file.Source, file.Resolve and Runner are, because this package may
// not import the file adapter.
type Ports struct {
	Source  func(string) (io.ReadCloser, error)
	Resolve func(string) (string, error)
	Run     Runner
}

// Builds are what the packages of each distribution are known to do with one
// library's CA file, keyed by the ID os-release gives - one table for each
// library a tool reads its CA file through.
type Builds map[string]distributionBuild

// distributionBuild is what one distribution's packages are known to do.
type distributionBuild struct {
	// bundles are every CA file a release of this distribution builds the
	// library to read, and every one of them has to be the platform store's file.
	bundles []string
	// packages is how the distribution records which package installed a file.
	packages packageDatabase
}

// packageDatabase answers whether a package installed a file.
type packageDatabase struct {
	name string
	owns func(ctx context.Context, ports Ports, file, pkg string) (bool, error)
}

var (
	dpkg = packageDatabase{name: "dpkg", owns: dpkgOwns}
	apk  = packageDatabase{name: "apk", owns: apkOwns}
	rpm  = packageDatabase{name: "rpm", owns: rpmOwns}
)

// debianBundle and redHatBundles are the files the two families build libcurl
// to read - the sources are on distributionBuilds.
var (
	debianBundle  = []string{"/etc/ssl/certs/ca-certificates.crt"}
	redHatBundles = []string{"/etc/pki/tls/certs/ca-bundle.crt", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"}
)

// LibcurlBuilds are the distributions whose packages this program knows the
// CA file of libcurl for - ADR110, condition 2: an ID with a source behind it,
// and never ID_LIKE, which would be a claim about derived distributions nobody
// measured.
//
// SOURCES, inviolable rule 18 - each distribution's own recipe for libcurl, read
// 2026-10-20:
//   - debian: debian/rules of curl 8.14.1-2+deb13u5 (trixie),
//     https://sources.debian.org/data/main/c/curl/8.14.1-2%2Bdeb13u5/debian/rules -
//     --with-ca-bundle=/etc/ssl/certs/ca-certificates.crt in CONFIGURE_ARGS, which
//     both flavours are configured with: OpenSSL for the curl tool, GnuTLS for git.
//   - ubuntu: debian/rules of curl 8.18.0-1ubuntu2 (26.04), the same line, at
//     https://git.launchpad.net/ubuntu/+source/curl/plain/debian/rules?h=ubuntu/resolute
//   - alpine: main/curl/APKBUILD of aports 3.24-stable (curl 8.22.0), at
//     https://gitlab.alpinelinux.org/alpine/aports/-/raw/3.24-stable/main/curl/APKBUILD
//   - rhel and centos: curl.spec of CentOS Stream 9 and 10, which RHEL is built
//     from, at https://gitlab.com/redhat/centos-stream/rpms/curl (c9s, c10s).
//   - rocky: SPECS/curl.spec of r9 and r10, https://git.rockylinux.org/staging/rpms/curl
//   - almalinux: SPECS/curl.spec of a9 and c10, https://git.almalinux.org/rpms/curl
//   - fedora: curl.spec of rawhide, https://src.fedoraproject.org/rpms/curl - its
//     changelog moves the file from ca-bundle.crt to tls-ca-bundle.pem in 8.10.1-2.
//
// MEASURED by S26 on 2026-10-20 in Debian 13, Ubuntu 26.04, Alpine 3.24 and RHEL
// 9.7: with nothing named, a root appended to that file was trusted by curl from
// the package, and by git from the Debian and Alpine ones. The other four stand on
// their recipes alone. That releases these were not read for build the same way
// is an ASSESSMENT, not a source.
//
// THE RED HAT FAMILY BUILDS TO TWO NAMES, and which one depends on the release -
// ca-bundle.crt in CentOS Stream 9, Rocky 10 and AlmaLinux c10, tls-ca-bundle.pem
// in CentOS Stream 10 and Fedora. Both are listed, so both have to be the
// platform store's file. The ca-certificates package links the first to the
// second - measured in RHEL 9.7 - so on an ordinary machine they are one file,
// and where somebody broke that link nothing here can say which one this release
// reads.
var LibcurlBuilds = Builds{
	"debian":    {bundles: debianBundle, packages: dpkg},
	"ubuntu":    {bundles: debianBundle, packages: dpkg},
	"alpine":    {bundles: debianBundle, packages: apk},
	"rhel":      {bundles: redHatBundles, packages: rpm},
	"centos":    {bundles: redHatBundles, packages: rpm},
	"rocky":     {bundles: redHatBundles, packages: rpm},
	"almalinux": {bundles: redHatBundles, packages: rpm},
	"fedora":    {bundles: redHatBundles, packages: rpm},
}

// OpenSSLBuilds are the distributions whose packages this program knows the
// default CA file of OpenSSL for - the file a program reads when it asks
// OpenSSL for its default store, node from a distribution's package among them
// (ADR111 part 6). It is OPENSSLDIR "/cert.pem", and SSL_CERT_FILE replaces it -
// include/internal/common.h and crypto/x509/by_file.c of OpenSSL's openssl-3.5
// branch, read 2026-10-20 at https://github.com/openssl/openssl/tree/openssl-3.5
//
// SOURCES, inviolable rule 18 - each distribution's own recipe for OpenSSL,
// read 2026-10-20, and every one passes --openssldir:
//   - debian: debian/rules of openssl 3.5.7-1~deb13u2 (trixie), /usr/lib/ssl, at
//     https://sources.debian.org/data/main/o/openssl/3.5.7-1~deb13u2/debian/rules
//   - ubuntu: debian/rules of openssl 3.5.5-1ubuntu3.7 (26.04), the same line, in
//     https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/openssl/3.5.5-1ubuntu3.7/openssl_3.5.5-1ubuntu3.7.debian.tar.xz
//   - alpine: main/openssl/APKBUILD of aports 3.24-stable (openssl 3.5.9),
//     /etc/ssl, at https://gitlab.alpinelinux.org/alpine/aports/-/raw/3.24-stable/main/openssl/APKBUILD
//   - rhel and centos: openssl.spec of CentOS Stream 9 and 10, /etc/pki/tls, at
//     https://gitlab.com/redhat/centos-stream/rpms/openssl (c9s, c10s).
//   - rocky: SPECS/openssl.spec of r9 and r10, https://git.rockylinux.org/staging/rpms/openssl
//   - almalinux: SPECS/openssl.spec of a9 and openssl.spec of a10,
//     https://git.almalinux.org/rpms/openssl
//
// MEASURED by S27 on 2026-10-20 in Debian 13, Ubuntu 26.04 and Alpine 3.24:
// cert.pem there leads to /etc/ssl/certs/ca-certificates.crt, and a root
// appended to that file was trusted by node from the package with nothing set.
// In RHEL 9.8 the same day /etc/pki/tls/cert.pem led to the file the platform
// store's row reads - the trust itself rests on the source there.
//
// FEDORA IS NOT HERE - measured by S27 in Fedora 44: its OpenSSL reads only a
// directory of hashed names, and /etc/pki/tls/cert.pem is not there (OBS186).
// The ca-certificates package of CentOS Stream 10 took that link away and
// brought it back (RHEL-109484 in its changelog), which is why the file is
// compared on the machine rather than assumed.
var OpenSSLBuilds = Builds{
	"debian":    {bundles: debianOpenSSL, packages: dpkg},
	"ubuntu":    {bundles: debianOpenSSL, packages: dpkg},
	"alpine":    {bundles: []string{"/etc/ssl/cert.pem"}, packages: apk},
	"rhel":      {bundles: redHatOpenSSL, packages: rpm},
	"centos":    {bundles: redHatOpenSSL, packages: rpm},
	"rocky":     {bundles: redHatOpenSSL, packages: rpm},
	"almalinux": {bundles: redHatOpenSSL, packages: rpm},
}

var (
	debianOpenSSL = []string{"/usr/lib/ssl/cert.pem"}
	redHatOpenSSL = []string{"/etc/pki/tls/cert.pem"}
)

// DeferToThePlatform writes the row of a tool on Linux that names no CA file:
// it defers to the platform's own store when the tool is the distribution's own
// build of a distribution in builds and reads that store's file, and otherwise
// says which of those does not hold. compiledIn is what the row says about a
// build left to its compiled-in file, and pkg is the package the distribution
// ships the tool in.
//
// binary is empty when no binary was found for the install, and then nothing
// can be said about its package.
func DeferToThePlatform(ctx context.Context, store report.TrustStore, ports Ports, builds Builds, binary, pkg,
	compiledIn string) report.TrustStore {
	instance, why := platformStoreOf(ctx, ports, builds, binary, pkg)
	if why != "" {
		store.NotAssessed = compiledIn + " - " + why
		return store
	}
	store.DefersTo = &report.StoreRef{Runtime: report.RuntimeSystemStore, Instance: instance}
	store.NotAssessed = fmt.Sprintf("this is %s's own build, and it reads the bundle system-store %s judges", instance, instance)
	return store
}

// platformStoreOf names the instance of the platform store this build judges
// by, or says why it does not.
//
// THE INSTANCE IS THE ONE THE PLATFORM STORE'S ROW CARRIES, because it comes
// from the same reader - a pointer at an instance no row has would be answered
// "this run has no answer from that store".
func platformStoreOf(ctx context.Context, ports Ports, builds Builds, binary, pkg string) (string, string) {
	id := Distribution(ports.Source, LinuxReleases)
	build, known := builds[id]
	switch {
	case !known:
		return "", fmt.Sprintf("which file that is, this program knows only for the packages of %s, and this "+
			"distribution is %q", knownDistributions(builds), id)
	case binary == "":
		return "", fmt.Sprintf("no %s binary was found for this install, so whether it is %s's own build was not "+
			"established", pkg, id)
	}
	owned, err := ownedBy(ctx, ports, build.packages, binary, pkg)
	switch {
	case err != nil:
		return "", fmt.Sprintf("whether %s is %s's own build was not established: %v", binary, id, err)
	case !owned:
		return "", fmt.Sprintf("%s, so it is not known to be %s's own build", build.packages.notOwned(binary, pkg), id)
	}
	if why := sameBundle(ports, id, build.bundles); why != "" {
		return "", why
	}
	return id, ""
}

// sameBundle says why the files a distribution builds libcurl to read are not
// the platform store's file, or returns the empty string when they are.
//
// THE STORE'S FILE IS ASKED OF THE FUNCTION ITS ROW ASKS, and a contract keeps
// the row that defers from naming a file of its own, so the comparison has to
// happen here - ADR110, condition 3.
//
// ONE FILE UNDER TWO NAMES IS ONE FILE. The comparison follows links, because a
// name that leads to the store's file reads exactly what the store's row read -
// measured in RHEL 9.7, where the name Go finds first is a link.
func sameBundle(ports Ports, id string, bundles []string) string {
	names := strings.Join(bundles, " or ")
	chosen, _, _ := FirstBundle(ports.Source, LinuxBundles)
	if chosen == "" {
		return fmt.Sprintf("%s's packages are built to read %s, and no CA bundle is at any of the places the "+
			"platform's own store is looked for", id, names)
	}
	for _, bundle := range bundles {
		if bundle != chosen && Resolved(ports.Resolve, bundle) != Resolved(ports.Resolve, chosen) {
			return fmt.Sprintf("%s's packages are built to read %s, and the platform's own store here is %s, which "+
				"is not the same file as %s", id, names, chosen, bundle)
		}
	}
	return ""
}

// knownDistributions names a table's distributions in a sentence, in a fixed
// order.
func knownDistributions(builds Builds) string {
	ids := slices.Sorted(maps.Keys(builds))
	return strings.Join(ids[:len(ids)-1], ", ") + " and " + ids[len(ids)-1]
}

// ownedBy asks the package database about the binary as found and, when it is
// reached through a link, about where the link leads.
//
// BOTH FORMS, BECAUSE DPKG KNOWS ONLY ONE OF THEM. Measured by S26 on
// 2026-10-20 in Debian 13: /bin links to usr/bin, and curl.list holds
// /usr/bin/curl and no line for /bin/curl - so a PATH that reaches /bin first
// would read as a curl from nowhere.
func ownedBy(ctx context.Context, ports Ports, db packageDatabase, binary, pkg string) (bool, error) {
	forms := []string{binary}
	if real := Resolved(ports.Resolve, binary); real != binary {
		forms = append(forms, real)
	}
	for _, file := range forms {
		owned, err := db.owns(ctx, ports, file, pkg)
		if owned || err != nil {
			return owned, err
		}
	}
	return false, nil
}

// notOwned is the sentence for a binary the database does not know.
func (db packageDatabase) notOwned(binary, pkg string) string {
	if db.name == rpm.name {
		return fmt.Sprintf("rpm -qf does not know %s as a file of any package", binary)
	}
	return fmt.Sprintf("%s does not list %s among the files of the %s package", db.name, binary, pkg)
}

// dpkgInfo is where dpkg keeps the list of files each package installed, one
// absolute path per line in <package>.list.
//
// MEASURED by S26 on 2026-10-20 in Debian 13: curl.list holds /usr/bin/curl and
// git.list /usr/bin/git, and only the libraries built to sit beside their other
// architectures carry one in the name - libcurl4t64:amd64.list. The tools do not.
const dpkgInfo = "/var/lib/dpkg/info/"

func dpkgOwns(_ context.Context, ports Ports, file, pkg string) (bool, error) {
	return anyLine(ports.Source, dpkgInfo+pkg+".list", func(line string) bool { return line == file })
}

// apkInstalled is apk's record of what each package installed.
//
// SOURCE, inviolable rule 18: Apk spec, "Installed Database V2", read 2026-10-20
// at https://wiki.alpinelinux.org/wiki/Apk_spec - the file is located at
// /lib/apk/db/installed, "F:" is a directory the package created and "R:" a file
// name relative to the preceding directory name. Records are the package index
// format, P: naming the package. MEASURED by S26 the same day in Alpine 3.24.1:
// P:curl, then F:usr/bin, then R:curl.
const apkInstalled = "/lib/apk/db/installed"

func apkOwns(_ context.Context, ports Ports, file, pkg string) (bool, error) {
	// THE PATHS ARE THE MACHINE'S, NOT THIS PLATFORM'S - slash-separated
	// whatever runs the tests, so path rather than filepath.
	directory, name := strings.TrimPrefix(path.Dir(file), "/"), path.Base(file)
	current, folder := "", ""
	return anyLine(ports.Source, apkInstalled, func(line string) bool {
		key, value, _ := strings.Cut(line, ":")
		switch key {
		case "":
			// A blank line ends a record, so nothing of it carries into the next.
			current, folder = "", ""
		case "P":
			current, folder = value, ""
		case "F":
			folder = value
		case "R":
			return current == pkg && folder == directory && value == name
		}
		return false
	})
}

// rpmBinary is the rpm the distribution installs - measured by S26 on
// 2026-10-20 in RHEL 9.7, beside /bin/rpm through the /bin link.
//
// THE ANSWER IS THE EXIT CODE ALONE, decided by the owner 2026-10-20: the
// package's name is printed text, and recognising somebody else's answer by its
// text is what inviolable rule 19 forbids. Measured the same day: 0 for
// /usr/bin/curl and for /bin/curl, 1 for a file no package installed and for a
// file that is not there. Its database is SQLite, which this program does not
// read without a dependency (rule 5) - so the one rpm reads is asked through it.
const rpmBinary = "/usr/bin/rpm"

func rpmOwns(ctx context.Context, ports Ports, file, _ string) (bool, error) {
	out, err := ports.Run(ctx, rpmBinary, "-qf", "--", file)
	if err != nil {
		return false, err
	}
	return out.ExitCode == 0, nil
}

// anyLine reports whether a line of a file satisfies match. A file that is not
// there holds no line, and a file that could not be read to the end is an error
// rather than a no - a list cut short cannot say a file is missing from it.
func anyLine(source func(string) (io.ReadCloser, error), file string, match func(string) bool) (bool, error) {
	reader, err := source(file)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = reader.Close() }()
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		if match(scanner.Text()) {
			return true, nil
		}
	}
	return false, scanner.Err()
}
