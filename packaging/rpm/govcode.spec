# govcode RPM for RHEL 8 and 9 (and rebuilds such as Rocky or Alma).
#
# This spec does NOT compile govcode. It packages the reproducible, signed
# release directory produced by scripts/build-release.sh, so the installed
# binary is byte-identical to the one whose SHA-256 is in the signed
# manifest and SLSA provenance. Stripping, debuginfo and build-id links are
# disabled for that reason. Build it with scripts/build-rpm.sh.

%global debug_package %{nil}
%global __os_install_post %{nil}
%global __brp_strip %{nil}
%define _build_id_links none

Name:           govcode
Version:        %{gc_version}
Release:        1%{?dist}
Summary:        Air-gapped coding agent for legacy code with signed audit and two-person approval
License:        MIT
URL:            https://github.com/sandy-t-shelvan/govcode
Source0:        govcode-%{gc_release}.tar
ExclusiveArch:  x86_64
BuildRequires:  selinux-policy-devel
BuildRequires:  make
Requires:       git >= 2.38
Requires:       bubblewrap
Requires(pre):  shadow-utils

%description
govcode runs a local coding model against one repository, records every
model exchange, command and decision in a hash-chained, per-user signed
audit log, and lands nothing without a human approval (two-person rule
optional). Network access is limited to loopback. This package installs the
signed release binary unmodified, with its manifest, SLSA provenance,
SBOM and AI-BOM.

%package selinux
Summary:        SELinux policy module for govcode state and configuration
BuildArch:      noarch
Requires:       %{name} = %{version}-%{release}
Requires:       selinux-policy-targeted
Requires(post): policycoreutils
Requires(postun): policycoreutils

%description selinux
Labels govcode's shared state (audit log, proposals, evidence) and its
root-owned configuration, and lets confined user domains use them.

%prep
%setup -q -n govcode-%{gc_release}

%build
# The binary is the signed release artifact and is not rebuilt. Only the
# SELinux module is compiled, against the build host's policy, so build the
# RPM on the same RHEL major version you deploy to.
make -C selinux -f %{_datadir}/selinux/devel/Makefile govcode.pp

%install
install -D -m 0755 bin/govcode %{buildroot}%{_bindir}/govcode
install -d -m 0755 %{buildroot}%{_datadir}/govcode
for f in manifest.json manifest.json.sig provenance.intoto.jsonl sbom.intoto.jsonl \
         sbom.cdx.json aibom.cdx.json SHA256SUMS; do
  install -m 0644 "$f" %{buildroot}%{_datadir}/govcode/
done
cp -r deploy docs models %{buildroot}%{_datadir}/govcode/
[ -d vscode ] && cp -r vscode %{buildroot}%{_datadir}/govcode/
install -d -m 0755 %{buildroot}%{_sysconfdir}/govcode
install -d -m 0755 %{buildroot}%{_sysconfdir}/govcode/trust
install -d -m 0755 %{buildroot}%{_sysconfdir}/govcode/keys
install -d -m 2770 %{buildroot}/var/lib/govcode
install -D -m 0644 selinux/govcode.pp %{buildroot}%{_datadir}/selinux/packages/govcode.pp

%pre
getent group govcode >/dev/null || groupadd -r govcode
exit 0

%post
# The binary verifies itself against the manifest at /usr/share/govcode;
# point trust.release_manifest and trust.release_provenance there.
exit 0

%post selinux
semodule -n -i %{_datadir}/selinux/packages/govcode.pp
if /usr/sbin/selinuxenabled; then
  load_policy
  restorecon -R /var/lib/govcode %{_sysconfdir}/govcode %{_bindir}/govcode || :
fi
exit 0

%postun selinux
if [ $1 -eq 0 ]; then
  semodule -n -r govcode >/dev/null 2>&1 || :
  if /usr/sbin/selinuxenabled; then
    load_policy
    restorecon -R /var/lib/govcode %{_sysconfdir}/govcode || :
  fi
fi
exit 0

%files
%license LICENSE
%doc README.md
%{_bindir}/govcode
%{_datadir}/govcode/
%dir %attr(0755,root,root) %{_sysconfdir}/govcode
%dir %attr(0755,root,root) %{_sysconfdir}/govcode/trust
%dir %attr(0755,root,root) %{_sysconfdir}/govcode/keys
%dir %attr(2770,root,govcode) /var/lib/govcode

%files selinux
%{_datadir}/selinux/packages/govcode.pp
