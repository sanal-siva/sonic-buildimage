from setuptools import setup, find_packages

setup(
    name="sonic-guardian",
    version="1.0.0",
    description="SONiC Guardian - Self-Healing Security Framework",
    author="SONiC Contributors",
    license="Apache 2.0",
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.9",
    install_requires=[
        "grype>=0.65.0",
        "requests>=2.28.0",
        "pyyaml>=6.0",
        "click>=8.0.0",
        "sonic-py-swscommon",
        "sonic-py-yang",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "pylint>=2.15",
            "flake8>=5.0",
            "black>=22.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "sonic-guardian-daemon=guardian.main:main",
            "security=guardian.cli:security",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Networking",
    ],
)
