Name:           vd_host
Version:        1.0.0
Release:        1%{?dist}
Summary:        QingCloud Desktop Host Server For Guest
Group:          Applications/System
License:        GPLv3+
URL:            http://www.yunify.com/
Source0:        %{name}-%{version}.tar.gz
BuildRequires:  systemd-devel glib2-devel libpciaccess-devel
BuildRequires:  libXrandr-devel libXinerama-devel libXfixes-devel
BuildRequires:  systemd-units desktop-file-utils
Requires(post): systemd-units
Requires(preun): systemd-units
Requires(postun): systemd-units

%description
QingCloud Desktop for Linux guests offering the following features:

Features:
* Communicate with vdagent server
* Server for guest agents


%prep
%setup -q
# mkdir -p %{_sysconfdir}/qing-cloud


%build
%configure --with-session-info=systemd --with-init-script=systemd
make %{?_smp_mflags} V=2


%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_sysconfdir}/qing-cloud
mkdir -p %{buildroot}%{_unitdir} 
cp -r ./data/vd_host.service  %{buildroot}%{_unitdir}
cp -r ./data/vd_host.target  %{buildroot}%{_unitdir}
cp -r ./data/qing-cloud/vd_host.conf %{buildroot}%{_sysconfdir}/qing-cloud
#cp -r ./src/vd_host %{_bindir}/vd_host
make install DESTDIR=$RPM_BUILD_ROOT V=2


%post
%systemd_post vd_host.service

%preun
%systemd_preun vd_host.service

%postun
%systemd_postun_with_restart vd_host.service


%files
%doc README.md
%config(noreplace) %{_sysconfdir}/qing-cloud/vd_host.conf
%{_unitdir}/vd_host.service
%{_unitdir}/vd_host.target
%{_bindir}/vd_host


%changelog
* Wed Dec 11 2019 Abel Lee <abelee@yunify.com> - 1.0.0-1
- First Release
