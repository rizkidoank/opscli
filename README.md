# opscli

opscli is ops cli :)

## Requirements

- Python3
- JIRA Username and Password. If you login using SSO, you can follow [How can I change or reset my my.atlassian.com password](https://confluence.atlassian.com/purchasing/how-can-i-change-or-reset-my-my-atlassian-com-password-321257579.html)

## Install opscli

Create virtualenv with Python3

```
virtualenv -p python3 opscli
```

Activate virtualenv

```
source opscli/bin/activate
```

Install opscli using pip

```
pip install git+https://github.com/traveloka/opscli.git
```

## Configure opscli

Before we can use opscli, we need to configure 

```
opscli configure
```

## Using opscli

To describe connectivity

```
opscli describe-connectivity --ticket-id <ticket_id>
```