#!/usr/bin/env bash

set -euo pipefail

cd ../..
mkdir vanilla-source-code
cd vanilla-source-code
git clone git@github.com:xlab-uiuc/6.12.9-viommu.git
git clone git@github.com:xlab-uiuc/qemu-viommu.git
