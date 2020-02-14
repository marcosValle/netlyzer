import os
from setuptools import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "Netlyzer",
    version = "0.0.1",
    author = "Marcos Valle",
    author_email = "marcos.valle01@gmail.com",
    description = ("Simple pcap file analyzer for generating metrics and indicators of malicious activity."),
    license = "MIT",
    keywords = "pcap malicious ddos network",
    packages=['netlyzer', 'tests'],
    long_description=read('README.md'),
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Topic :: Utilities",
    ],
)
