from setuptools import setup, find_packages

setup(
    name='pycoin',
    version='0.1.0',
    author = 'Christian Decker',
    author_email = 'cdecker@tik.ee.ethz.ch',
    packages = find_packages(exclude=["tests"]),
    url='http://www.disco.ethz.ch/members/cdecker.html',
    license='LICENSE.txt',
    description='A minimalistic bitcoin protocol implementation aimed at protocol testing and measurements',
    long_description=open('README.md').read(),
    install_requires=[
        "Twisted >= 13.1.0",
        "gevent"
    ],
    setup_requires=['nose>=1.0'],
    test_suite='test',
)
