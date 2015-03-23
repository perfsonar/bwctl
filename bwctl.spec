%{!?python_sitelib: %define python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}

Name: bwctl
Version: 2.0a1
Release: 1%{?dist}
Summary: Network measurement scheduler
Group: *Development/Libraries*
URL: http://software.internet2.edu/bwctl
License: Apache License v2.0

Source: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch: noarch

BuildRequires: python-setuptools

# Make the 'bwctl' a metapackage that installs the client and server
Requires: bwctl-client
Requires: bwctl-server

%description
BWCTL is a command line client application and a scheduling and policy daemon
that wraps various network measurement tools including iperf, iperf3, owamp
ping and traceroute.

%package client
Summary: bwctl client
Group: Applications/Network
Requires:   iperf, iperf3 >= 3.0.11, bwctl-shared
%description client
bwctl command line tool for scheduling bandwidth measurements with a bwctl
server.

%package server
Summary: bwctl server
Group: Applications/Network
Requires: chkconfig, initscripts, shadow-utils, coreutils
Requires:   iperf, iperf3 >= 3.0.11, bwctl-shared
%description server
bwctl server

%package shared
Summary: bwctl shared components
Group: Applications/Network

Requires: python-psutil
Requires: python-configobj
Requires: py-radix
Requires: python-cherrypy
Requires: python-routes
Requires: python-setuptools
Requires: python-simplejson
Requires: uuid

%description shared
Shared components used by the bwctl server and client RPMs

%prep
%setup -q

%build
%{__python} setup.py build

%install
%{__python} setup.py install --skip-build --root %{buildroot}
install -D -m755 scripts/bwctld.init %{buildroot}/%{_initrddir}/bwctld

%files

%files client
%defattr(-,root,root)
%{_bindir}/bwctl2
%{_bindir}/bwping2
%{_bindir}/bwtraceroute2

%files shared
%defattr(-,root,root)
%doc
%{python_sitelib}/bwctl/*
%{python_sitelib}/bwctl*.egg-info/

%files server
%defattr(-,root,root)
%doc
%{_bindir}/bwctld
%config(noreplace) %{_sysconfdir}/bwctld/bwctld.conf
#%config(noreplace) %{_sysconfdir}/bwctld/bwctld.limits
%config(noreplace) %{_initrddir}/bwctld

%post server
if [ $1 = 0 ]; then
    /sbin/chkconfig --add bwctld
fi

%preun server
if [ $1 = 0 ]; then
    /sbin/service bwctld stop >/dev/null 2>&1
    /sbin/chkconfig --del bwctld
fi

%changelog
* Wed Mar 11 2015 Aaron Brown <aaron@internet2.edu> - 2.0a1
Initial version
