from setuptools import setup, find_packages

setup(
    name='opscli',
    version='1.0.0',
    packages=find_packages(exclude=['test*']),
    url='https://github.com/rizkidoank/opscli',
    license='MIT',
    author='rizki',
    author_email='rizki@rizkidoank.com',
    description='operational cli tools',
    classifiers=[
        'Development Status :: 2 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: System :: Systems Administration',
        'Programming Language :: Python :: 2',
    ],
    keywords='devops operational sysadmin',
    install_requires=[
        'boto3',
        'tabulate',
        'jira',
        'ipaddress',
        'jinja2',
        'pbr', 'botocore'
    ],
    package_data={
       'opscli': ['templates/*.jinja2'],
    },
    include_package_data=True,
    python_requires='>=2.7,<3',
    entry_points={
        'console_scripts': [
            'opscli=opscli.main:main'
        ],
    }
)
