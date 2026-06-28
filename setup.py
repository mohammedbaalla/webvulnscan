from setuptools import setup, find_packages

setup(
    name="webvulnscan",
    version="1.0.0",
    description="Advanced Web Vulnerability Scanner — XSS, SQLi, CSRF, Headers",
    author="Your Name",
    author_email="you@example.com",
    url="https://github.com/yourusername/web-vuln-scanner",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=4.9.0",
        "urllib3>=2.0.0",
    ],
    entry_points={
        "console_scripts": [
            "webvulnscan=scan:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
        "Environment :: Console",
    ],
)
