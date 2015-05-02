from setuptools import setup, find_packages

setup(
    name='pycoin',
    version='0.1.0',
    author='Christian Decker',
    author_email='cdecker@tik.ee.ethz.ch',
    packages=find_packages(exclude=["tests"]),
    url='http://www.disco.ethz.ch/members/cdecker.html',
    license='LICENSE.txt',
    description=('A minimalistic bitcoin protocol implementation'),
    long_description=open('README.md').read(),
    install_requires=[
        "gevent",
        "six==1.8.0"
    ],
    setup_requires=['nose>=1.0'],
    test_suite='tests',
    tests_require=['mock'],
)
