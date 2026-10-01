from setuptools import setup, find_packages

setup(name="sonic-guardian", version="2.0.0", description="Resource-bounded SONiC security inventory and evidence agent",
      author="SONiC Contributors", license="Apache-2.0", packages=find_packages(exclude=["tests", "tests.*"]),
      python_requires=">=3.9", install_requires=["requests>=2.28", "PyYAML>=6", "click>=8"],
      entry_points={"console_scripts": ["sonic-guardian-daemon=guardian.main:main", "security=guardian.cli:security"]})
