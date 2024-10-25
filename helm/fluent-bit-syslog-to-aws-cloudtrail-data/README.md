<!--
SPDX-FileCopyrightText: 2024 Dominik Wombacher <dominik@wombacher.cc>

SPDX-License-Identifier: CC0-1.0
-->

# Helm Chart: Fluent Bit Syslog to AWS CloudTrail Data

Run a Fluent Bit deployment with a pre-configured Syslog input and
AWS CloudTrail Data output. Leverages the `fluent-bit-aws-cloudtrail-data`
Container Image
([Dockerfile](https://git.sr.ht/~wombelix/fluent-bit-output-plugin-aws-cloudtrail-data/tree/main/item/container/Dockerfile)
, [Repository](https://quay.io/repository/wombelix/fluent-bit-syslog-to-aws-cloudtrail-data)).

[![REUSE status](https://api.reuse.software/badge/git.sr.ht/~wombelix/fluent-bit-output-plugin-aws-cloudtrail-data)](https://api.reuse.software/info/git.sr.ht/~wombelix/fluent-bit-output-plugin-aws-cloudtrail-data)
[![builds.sr.ht status](https://builds.sr.ht/~wombelix/fluent-bit-output-plugin-aws-cloudtrail-data.svg)](https://builds.sr.ht/~wombelix/fluent-bit-output-plugin-aws-cloudtrail-data?)

## Table of Contents

* [Release](#release)
* [Run](#run)
* [Source](#source)
* [Contribute](#contribute)
* [License](#license)

## Release

The Helm Chart is automatically
[build and pushed](https://git.sr.ht/~wombelix/fluent-bit-output-plugin-aws-cloudtrail-data/tree/main/item/.build.yml)
to
[Quay.io](https://quay.io/repository/wombelix/fluent-bit-syslog-to-aws-cloudtrail-data)
on every new commit to the git repository.

## Run

Use `helm install` to deploy the chart, ensure to set the version
and the path to a customized `values.yaml` accordingly.

```
helm install syslog-to-aws-cloudtrail-data \
    --version 0.0.1 \
    oci://quay.io/repository/wombelix/fluent-bit-syslog-to-aws-cloudtrail-data \
    --values values.yaml
```

Please refer to
[values.yaml](https://git.sr.ht/~wombelix/fluent-bit-output-plugin-aws-cloudtrail-data/tree/main/item/helm/fluent-bit-syslog-to-aws-cloudtrail-data/values.yaml)
for a complete overview of all available configuration options.

It's required to set `channelArn` and to ensure that the AWS Region was
either correctly auto-discovered or to set `awsRegion` manually.

More
[information and additional requirements](https://git.sr.ht/~wombelix/fluent-bit-output-plugin-aws-cloudtrail-data#run)
of the `aws-cloudtrail-data` plugin.

Optional, but helpful for troubleshooting purposes, is to set
`debug` and/or `enableStandardOutput` to `true`.

The plugin, container and helm chart was initially developed to push
[NeuVector](https://github.com/neuvector/neuvector)
logs and events to AWS CloudTrail Lake. The chart is generic and
can be used with any software or system that supports Syslog.

For usage with NeuVector, it's recommend to deploy in the same namespace.
Adjust the `namespace` value accordingly, for a standalone Helm deployment
`neuvector` and for a Rancher deployment `cattle-neuvector-system`.

## Source

The primary location is:
[git.sr.ht/~wombelix/fluent-bit-output-plugin-aws-cloudtrail-data](https://git.sr.ht/~wombelix/fluent-bit-output-plugin-aws-cloudtrail-data)
in sub-folder `helm/fluent-bit-syslog-to-aws-cloudtrail-data`.

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
