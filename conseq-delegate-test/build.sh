#!/bin/bash
set -ex

cp ../conseq/helper.py helper.py
docker build -t conseq-delegate-test .
