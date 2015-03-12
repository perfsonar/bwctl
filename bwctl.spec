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

Requires: python-psutil
Requires: python-configobj
Requires: py-radix
Requires: python-cherrypy
Requires: python-routes
Requires: python-simplejson

Requires(post):	  chkconfig
Requires(preun):  chkconfig
Requires(preun):  initscripts
Requires(postun): initscripts

%description
BWCTL is a command line client application and a scheduling and policy daemon
that wraps various network measurement tools including iperf, iperf3, owamp
ping and traceroute.

%prep
%setup -q

%build
%{__python} setup.py build

%install
%{__python} setup.py install --skip-build --root %{buildroot}
#install -m755 init_scripts/bwctld.init %{buildroot}/%{_initrddir}/bwctld

%files
%defattr(-,root,root)
%doc
%{_bindir}/bw*
%{python_sitelib}/bwctl/*
%{python_sitelib}/bwctl*.egg-info/
%config(noreplace) %{_sysconfdir}/bwctld/bwctld.conf
#%config(noreplace) %{_sysconfdir}/bwctld/bwctld.limits
#%config(noreplace) %{_initrddir}/bwctld

#%post
#if [ $1 = 0 ]; then
#    /sbin/chkconfig --add bwctld
#fi
#
#%preun
#if [ $1 = 0 ]; then
#    /sbin/service bwctld stop >/dev/null 2>&1
#    /sbin/chkconfig --del bwctld
#fi

%changelog
* Wed Mar 11 2015 Aaron Brown <aaron@internet2.edu> - 2.0a1
Initial version
