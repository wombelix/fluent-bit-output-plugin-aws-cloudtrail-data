# SPDX-FileCopyrightText: 2024 Dominik Wombacher <dominik@wombacher.cc>
#
# SPDX-License-Identifier: CC0-1.0


# Temporary builder to compile fluent bit plugin from source
FROM docker.io/golang:1.22.7 as builder

RUN git clone https://git.sr.ht/~wombelix/fluent-bit-output-plugin-aws-cloudtrail-data /aws-cloudtrail-data
WORKDIR /aws-cloudtrail-data
RUN mkdir dist \
    && go build -buildmode=c-shared -o aws-cloudtrail-data.so . \
    && cp -r README.md \
    CHANGELOG.md \
    CHANGELOG.md.license \
    LICENSES/ \
    dist/


# Release image
FROM cr.fluentbit.io/fluent/fluent-bit:3.1.9

LABEL description="Fluent Bit AWS CloudTrail Data container image" \
    author="Dominik Wombacher <dominik@wombacher.cc>" \
    org.opencontainers.image.description="Fluent Bit AWS CloudTrail Data container image" \
    org.opencontainers.image.title="Fluent Bit AWS CloudTrail Data" \
    org.opencontainers.image.licenses="Apache-2.0" \
    org.opencontainers.image.source="https://git.sr.ht/~wombelix/fluent-bit-output-plugin-aws-cloudtrail-data" \
    org.opencontainers.image.documentation="https://git.sr.ht/~wombelix/fluent-bit-output-plugin-aws-cloudtrail-data" \
    org.opencontainers.image.authors="Dominik Wombacher <dominik@wombacher.cc>" \
    org.opencontainers.image.base.name="cr.fluentbit.io/fluent/fluent-bit:latest"

ARG AWS_CLOUDTRAIL_DATA_CHANNELARN
ENV AWS_CLOUDTRAIL_DATA_CHANNELARN=$AWS_CLOUDTRAIL_DATA_CHANNELARN

COPY --from=builder /aws-cloudtrail-data/aws-cloudtrail-data.so /fluent-bit/aws-cloudtrail-data.so
COPY --from=builder /aws-cloudtrail-data/dist/ /fluent-bit/aws-cloudtrail-data/

ENTRYPOINT [ "/fluent-bit/bin/fluent-bit" ]
CMD ["/fluent-bit/bin/fluent-bit", "-c", "/fluent-bit/etc/fluent-bit.conf", "-e", "/fluent-bit/aws-cloudtrail-data.so"]
