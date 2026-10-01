from setuptools import setup, find_packages

setup(name="sonic-smart-patch", version="3.1.0", description="Resource-bounded SONiC security inventory and evidence agent",
      author="SONiC Contributors", license="Apache-2.0", packages=find_packages(exclude=["tests", "tests.*"]),
      python_requires=">=3.9", install_requires=["requests>=2.28", "PyYAML>=6", "click>=8"],
      entry_points={"console_scripts": ["sonic-smart-patch-daemon=smart_patch.main:main", "security=smart_patch.cli:security"]})
