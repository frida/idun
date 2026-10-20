%global frida_deps 20261022
%ifarch x86_64
%global frida_host linux-x86_64
%endif
%ifarch aarch64
%global frida_host linux-arm64
%endif

Name:           idun
Version:        0.0.0
Release:        1%{?dist}
Summary:        Library and daemon for talking to Apple devices over CoreDevice
License:        wxWindows
URL:            https://github.com/frida/idun
Source0:        %{name}-%{version}.tar.xz
%ifarch x86_64
Source1:        https://build.frida.re/deps/%{frida_deps}/toolchain-linux-x86_64.tar.xz
%endif
%ifarch aarch64
Source1:        https://build.frida.re/deps/%{frida_deps}/toolchain-linux-arm64.tar.xz
%endif

BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  git
BuildRequires:  python3
BuildRequires:  efni-devel
BuildRequires:  glib2-devel
BuildRequires:  libgee-devel
BuildRequires:  json-glib-devel
BuildRequires:  libnghttp2-devel
BuildRequires:  openssl-devel
BuildRequires:  ngtcp2-devel
BuildRequires:  ngtcp2-crypto-ossl-devel
BuildRequires:  libusb1-devel
BuildRequires:  gstreamer1-devel
BuildRequires:  gstreamer1-plugins-base-devel
BuildRequires:  qt6-qtdeclarative-devel
BuildRequires:  gobject-introspection-devel
BuildRequires:  systemd-rpm-macros

%description
Library and daemon for talking to Apple devices over CoreDevice, with a
GStreamer element and a Quickshell module for screen mirroring.

%package        devel
Summary:        Development files for %{name}
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description    devel
Headers, Vala bindings and GObject introspection data for %{name}.

%package        -n gstreamer1-plugin-idun
Summary:        GStreamer element for Apple device screen mirroring
Requires:       %{name}%{?_isa} = %{version}-%{release}
Requires:       gstreamer1-plugins-good%{?_isa}

%description    -n gstreamer1-plugin-idun
Provides the idunscreensrc element.

%package        qml
Summary:        QML module for Apple device screen mirroring
Requires:       %{name}%{?_isa} = %{version}-%{release}
Requires:       gstreamer1-plugin-idun%{?_isa} = %{version}-%{release}
Requires:       gstreamer1-plugins-good%{?_isa}
Recommends:     gstreamer1-libav

%description    qml
Provides the Idun.Screen QML module.

%prep
%autosetup
mkdir -p deps
cp %{SOURCE1} deps/
python3 releng/deps.py sync toolchain %{frida_host} deps/toolchain-%{frida_host}

%build
export FRIDA_VERSION=%{version}
./configure --prefix=%{_prefix} --enable-shared --enable-symbols --without-prebuilds=sdk
make

%install
DESTDIR=%{buildroot} make install

%files
%license COPYING
%{_bindir}/idund
%{_libdir}/libidun-1.0.so.0*
%{_libdir}/girepository-1.0/Idun-1.0.typelib
%{_userunitdir}/idund.service
%{_datadir}/dbus-1/services/org.freedesktop.Idun1.service

%files -n gstreamer1-plugin-idun
%{_libdir}/gstreamer-1.0/libgstidun.so

%files qml
%{_libdir}/qt6/qml/Idun/

%files devel
%{_includedir}/idun-1.0/
%{_libdir}/libidun-1.0.so
%{_libdir}/pkgconfig/idun-1.0.pc
%{_datadir}/gir-1.0/Idun-1.0.gir
%{_datadir}/vala/vapi/idun-1.0.vapi

%changelog
* Tue Oct 20 2026 Ole André Vadla Ravnås <oleavr@frida.re> - 0.0.0-1
- Initial package
