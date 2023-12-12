import setuptools
from mend_sbom_cli._version import __version__, __tool_name__, __description__

mend_name = f"mend_{__tool_name__}"

setuptools.setup(
    name=mend_name,
    entry_points={
        'console_scripts': [
            f'{__tool_name__}={mend_name}.{__tool_name__}:main'
        ]},
    version=__version__,
    author="Mend Professional Services",
    author_email="ps@mend.io",
    description=__description__,
    url=f"https://github.com/mend-toolkit/{__tool_name__.replace('_', '-')}",
    license='LICENSE.txt',
    packages=setuptools.find_packages(),
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    install_requires=[line.strip() for line in open("requirements.txt").readlines()],
    python_requires='>=3.9',
    classifiers=[
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
)
