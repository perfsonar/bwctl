PACKAGE=bwctl2
VERSION=$(shell rpm -q --qf "%{VERSION}\n" --specfile ${PACKAGE}.spec)
RELEASE=$(shell rpm -q --qf "%{RELEASE}\n" --specfile ${PACKAGE}.spec)

RPM_FLAGS=--define "_topdir ${PWD}" --define "_specdir ${PWD}" --define "_sourcedir ${PWD}/dist" --define "_srcrpmdir ${PWD}" --define "_rpmdir ${PWD}" --define "_builddir ${PWD}"

default:
	@echo No need to build the package. Just run \"make install\"

archive:
	@python setup.py sdist --formats=gztar > /dev/null
	@echo "The archive is in dist/${PACKAGE}-$(VERSION).tar.gz"

srpm: archive
	@rpmbuild -bs ${RPM_FLAGS} ${PACKAGE}.spec

install:
	@python setup.py install
