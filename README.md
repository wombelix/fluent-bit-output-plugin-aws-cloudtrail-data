<!--
SPDX-FileCopyrightText: 2024 Dominik Wombacher <dominik@wombacher.cc>

SPDX-License-Identifier: CC0-1.0
-->

# Fluent Bit: Output Plugin for AWS CloudTrail Data Service

Golang based plugin to ingest events into AWS CloudTrail Lake
through the CloudTrail Data Service by calling
[PutAuditEvents](https://docs.aws.amazon.com/awscloudtraildata/latest/APIReference/API_PutAuditEvents.html).

[![REUSE status](https://api.reuse.software/badge/git.sr.ht/~wombelix/fluent-bit-output-plugin-aws-cloudtrail-data)](https://api.reuse.software/info/git.sr.ht/~wombelix/fluent-bit-output-plugin-aws-cloudtrail-data)
[![builds.sr.ht status](https://builds.sr.ht/~wombelix/fluent-bit-output-plugin-aws-cloudtrail-data.svg)](https://builds.sr.ht/~wombelix/fluent-bit-output-plugin-aws-cloudtrail-data?)

## Table of Contents

* [Release](#release)
* [Build](#build)
* [Run](#run)
* [Source](#source)
* [Contribute](#contribute)
* [License](#license)

## Release

Container images are automatically
[build and pushed](https://git.sr.ht/~wombelix/fluent-bit-output-plugin-aws-cloudtrail-data/tree/main/item/.build.yml)
to
[Quay.io](https://quay.io/repository/wombelix/fluent-bit-aws-cloudtrail-data).
Every image is tagged with the git commit hash.
The `main` tag follows the git branch `main`.
`vX.Y.X` tags match the git tags and `latest`
points to the most recent release version.

Automated publication of the pre-build binary `aws-cloudtrail-data.so`
is planned but not yet implemented.

## Build

To build from source you need `go` in version `1.22.7` or higher installed on
your system. Then clone the repository and run `go build`, example:

```
git clone https://git.sr.ht/~wombelix/fluent-bit-output-plugin-aws-cloudtrail-data

cd fluent-bit-output-plugin-aws-cloudtrail-data

go build -buildmode=c-shared -o aws-cloudtrail-data.so .
```

## Run

To get started, you need a
[Event data store](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/query-event-data-store.html)
with a
[custom integration](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/query-event-data-store-integration-custom.html)
in
[AWS CloudTrail Lake](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-lake.html).

The Fluent Bit parameter `ChannelArn` or Environment variable `AWS_CLOUDTRAIL_DATA_CHANNELARN`
is required and has to be set to the Arn of your custom integration.

You also have to modify your IAM Role of the User or Service
that runs Fluent Bit to allow `PutAuditEvents` to the Channel, example:

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudtrail-data:PutAuditEvents"
            ],
            "Resource": "arn:aws:cloudtrail:<region>>:<account>>:channel/<integration>"
        }
    ]
}
```

Further reading:
[AWS CloudTrail resource-based policy examples](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/security_iam_resource-based-policy-examples.html)

The plugin will load your AWS config based on the default credential chain
of the AWS SDK Go v2. Further reading:
[Specifying Credentials](https://aws.github.io/aws-sdk-go-v2/docs/configuring-sdk/#specifying-credentials)

Please ensure that the Environment variable `AWS_REGION` is set to the
to region of your Integration Channel. This might be required even
with a successful credential auto discover.

Depending on how you run `fluent-bit` you have to adjust the parameter
to load the plugin and use it as output, example:

```
fluent-bit -e ./aws-cloudtrail-data.so -o aws-cloudtrail-data -p ChannelArn=arn:aws:cloudtrail:<region>:<account>:channel/<integration>
```

The plugin supports the Fluent Bit debug environment variable `FLB_LOG_LEVEL`.
If the variable exist and is set to `DEBUG`,
it enables the Debug output of the plugin too.

## Source

The primary location is:
[git.sr.ht/~wombelix/fluent-bit-output-plugin-aws-cloudtrail-data](https://git.sr.ht/~wombelix/fluent-bit-output-plugin-aws-cloudtrail-data)

Mirrors are available on
[Codeberg](https://codeberg.org/wombelix/fluent-bit-output-plugin-aws-cloudtrail-data),
[Gitlab](https://gitlab.com/wombelix/fluent-bit-output-plugin-aws-cloudtrail-data)
and
[Github](https://github.com/wombelix/fluent-bit-output-plugin-aws-cloudtrail-data).

## Contribute

Please don't hesitate to provide Feedback,
open an Issue or create a Pull / Merge Request.

Just pick the workflow or platform you prefer and are most comfortable with.

Feedback, bug reports or patches to my sr.ht list
[~wombelix/inbox@lists.sr.ht](https://lists.sr.ht/~wombelix/inbox) or via
[Email and Instant Messaging](https://dominik.wombacher.cc/pages/contact.html)
are also always welcome.

## License

Unless otherwise stated: `Apache-2.0`

All files contain license information either as
`header comment` or `corresponding .license` file.

[REUSE](https://reuse.software) from the [FSFE](https://fsfe.org/)
implemented to verify license and copyright compliance.
