Name:           soft_fido2
Version:        0.4.0
Release:        1%{?dist}
Summary:        Software FIDO2 platform passkey authenticator (UHID)
License:        MIT
URL:            https://github.com/lachlan-ibm/soft-fido2
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  python3-pip
BuildRequires:  python3-build
BuildRequires:  python3-setuptools
BuildRequires:  python3-wheel

# Fedora 43 ships python3-cryptography 46.x; the wheel metadata auto-generates
# a python3.14dist(cryptography) >= 48 requirement that blocks installation.
# Filter it out until the repo catches up — the Requires: python3-cryptography
# below still ensures the package is present at the RPM level.
%global __requires_exclude ^python3\\.14dist\\(cryptography\\).*$

# ── Core Python deps (from pyproject.toml) ──────────────────────────────────
Requires:       python3-cryptography
Requires:       python3-cbor2
Requires:       python3-asn1
Requires:       python3-jwt

# ── UX / D-Bus / notifications ──────────────────────────────────────────────
# python3-pyqt6 hard-requires python3-pyqt6-base which carries the Qt6 runtime
# shared-library deps — RPM auto-dep resolves them; do not add qt6-* here.
Requires:       python3-pyqt6
Requires:       python3-jeepney
Requires:       python3-setproctitle
Requires:       python3-dbus

# ── Biometric (fprintd) — Recommends ────────────────────────────────────────
# Installed by dnf by default; skipped silently if unresolvable.
# The Python code communicates with fprintd over D-Bus via python3-dbus.
Recommends:     fprintd

# ── TPM 2.0 — Recommends ────────────────────────────────────────────────────
# Installed by dnf by default; skipped silently on machines with no TPM chip.
# tpm2-abrmd is the userspace resource manager daemon required by tpm2-pytss
# to communicate with the TPM device (/dev/tpmrm0).
Recommends:     tpm2-tss
Recommends:     tpm2-abrmd
Recommends:     python3-tpm2-pytss

%description
soft_fido2 is a software FIDO2/WebAuthn platform passkey authenticator
that emulates a USB HID device via the Linux UHID kernel module.

Supports biometric verification (fprintd), TPM 2.0 key storage, and
Qt6-based system tray UI with D-Bus notifications.

%prep
%autosetup -n %{name}-%{version}

%build
GITHUB_RUN_NUMBER=0 python3 -m build --wheel --no-isolation

%install
python3 -m pip install \
    --no-deps \
    --no-build-isolation \
    --root %{buildroot} \
    --prefix /usr \
    dist/*.whl

# Ship the rpmbuild user unit into the system-wide user unit drop-in dir
install -Dm644 rpmbuild/passkey.service \
    %{buildroot}/usr/lib/systemd/user/passkey.service

# Ship the udev rule
install -Dm644 rpmbuild/10-uhid.rules \
    %{buildroot}/etc/udev/rules.d/10-uhid.rules

# Ship the modules-load.d snippet
install -Dm644 rpmbuild/uhid.conf \
    %{buildroot}/etc/modules-load.d/uhid.conf

# Ship the env file template to /usr/share (reference copy, never modified by the package)
install -Dm644 rpmbuild/passkey.env \
    %{buildroot}/usr/share/soft_fido2/passkey.env.example

# Ship the skeleton config so every future user created via useradd gets it automatically
install -Dm600 rpmbuild/passkey.env \
    %{buildroot}/etc/skel/.fido2/passkey.env

%files
%license LICENSE
%{python3_sitelib}/soft_fido2/
%{python3_sitelib}/soft_fido2*.dist-info/
/usr/lib/systemd/user/passkey.service
/etc/udev/rules.d/10-uhid.rules
/etc/modules-load.d/uhid.conf
%{_datadir}/soft_fido2/passkey.env.example
%{_sysconfdir}/skel/.fido2/passkey.env

%post
# ── UHID kernel module ───────────────────────────────────────────────────────
modprobe uhid 2>/dev/null || true

# ── uhid system group ────────────────────────────────────────────────────────
# -r = system group (low GID, required for udev rules)
getent group uhid >/dev/null || groupadd -r uhid

# ── enroll the invoking user into the uhid group ─────────────────────────────
# $SUDO_USER is set when the user ran: sudo dnf install ...
# $PKEXEC_UID is set when PackageKit / GNOME Software ran the install.
_ENROLL_USER=""
if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
    _ENROLL_USER="${SUDO_USER}"
elif [ -n "${PKEXEC_UID:-}" ]; then
    _ENROLL_USER="$(getent passwd "${PKEXEC_UID}" | cut -d: -f1)"
fi

if [ -n "${_ENROLL_USER}" ]; then
    usermod -aG uhid "${_ENROLL_USER}"
    echo "Added '${_ENROLL_USER}' to the uhid group."
    if getent group tss >/dev/null; then
        usermod -aG tss "${_ENROLL_USER}"
        echo "Added '${_ENROLL_USER}' to the tss group."
    fi
else
    echo "Could not detect the desktop user — run manually:"
    echo "  sudo usermod -aG uhid \$USER"
    echo "  sudo usermod -aG tss \$USER"
fi

# ── copy skel config to the installing user's home if not already present ────
# Replace the literal %h placeholder with the user's real home directory so
# FIDO_HOME resolves correctly at runtime (systemd does not expand %h inside
# EnvironmentFile values, only in unit fields).
if [ -n "${_ENROLL_USER}" ]; then
    _HOME=$(getent passwd "${_ENROLL_USER}" | cut -d: -f6)
    if [ -n "${_HOME}" ] && [ ! -f "${_HOME}/.fido2/passkey.env" ]; then
        install -dm700 -o "${_ENROLL_USER}" -g "${_ENROLL_USER}" "${_HOME}/.fido2"
        install -m600 -o "${_ENROLL_USER}" -g "${_ENROLL_USER}" \
            /etc/skel/.fido2/passkey.env \
            "${_HOME}/.fido2/passkey.env"
        sed -i "s|FIDO_HOME=%h/|FIDO_HOME=${_HOME}/|" "${_HOME}/.fido2/passkey.env"
        echo "Created ${_HOME}/.fido2/passkey.env"
    fi
fi

# ── globally enable the passkey user service for all users ───────────────────
# Writes the enable symlink into /etc/systemd/user/default.target.wants/
# without needing a live user D-Bus session.
systemctl --global enable passkey.service 2>/dev/null || true

# ── reload udev so /dev/uhid gets GROUP=uhid immediately ─────────────────────
udevadm control --reload-rules
udevadm trigger --subsystem-match=misc

echo ""
echo "soft_fido2 installed. Log out and back in for group membership to take effect."
echo "The passkey service will start automatically at your next graphical login."

%preun
if [ $1 -eq 0 ]; then
    # Package is being removed (not upgraded)
    systemctl --global disable passkey.service 2>/dev/null || true
    rm -f /etc/modules-load.d/uhid.conf
    rm -f /etc/udev/rules.d/10-uhid.rules
    udevadm control --reload-rules
    udevadm trigger --subsystem-match=misc
fi

%changelog
* %(date "+%a %b %d %Y") soft_fido2 packager <lgleeson@au1.ibm.com> - 0.4.0-1
- Initial RPM package
