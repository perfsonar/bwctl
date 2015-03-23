#!/usr/bin/env python

from setuptools import setup
import glob

setup(name='bwctl',
        version='2.0a1',
        description='BWCTL Measurement Daemon',
        author='Aaron Brown',
        author_email='aaron@internet2.edu',
        url='http://software.internet2.edu/bwctl/',
        packages=[
           'bwctl',
           'bwctl.client',
           'bwctl.dependencies',
           'bwctl.dependencies.requests',
           'bwctl.dependencies.requests.packages',
           'bwctl.dependencies.requests.packages.chardet',
           'bwctl.dependencies.requests.packages.urllib3',
           'bwctl.dependencies.requests.packages.urllib3.packages',
           'bwctl.dependencies.requests.packages.urllib3.packages.ssl_match_hostname',
           'bwctl.dependencies.requests.packages.urllib3.contrib',
           'bwctl.dependencies.requests.packages.urllib3.util',
           'bwctl.jsonobject',
           'bwctl.protocol',
           'bwctl.protocol.legacy',
           'bwctl.protocol.coordinator',
           'bwctl.protocol.v2',
           'bwctl.server',
           'bwctl.server.tests_db',
           'bwctl.tool_types'
        ],
        install_requires=[
                          'cherrypy',
                          'configobj',
                          'psutil',
                          'simplejson',
                         ],
        entry_points={
            'console_scripts': [
                'bwctld = bwctl.server.bwctl_server:bwctld',
                'bwctl2 = bwctl.client.bwctl_client:bwctl_client',
                'bwping2 = bwctl.client.bwctl_client:bwctl_client',
                'bwtraceroute2 = bwctl.client.bwctl_client:bwctl_client',
            ]
        },
        data_files=[
            ('/etc/bwctld', glob.glob('etc/*.conf')),
        ],
        classifiers=[
            'Development Status :: 5 - Production/Stable',
            'Intended Audience :: Developers',
            'Intended Audience :: Telecommunications Industry',
            'Environment :: Console',
            'License :: OSI Approved :: Apache Software License',
            'Operating System :: POSIX',
            'Programming Language :: Python :: 2',
            'Topic :: Internet',
            'Topic :: System :: Networking',
            'Topic :: Software Development :: Libraries',
        ],
    )
