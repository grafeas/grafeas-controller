#!/bin/bash

# Copyright 2018 The Skaffold Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

export DOCKER_NAMESPACE=gcr.io/kritis-int-test
source $KOKORO_GFILE_DIR/common.sh

pushd $KOKORO_ARTIFACTS_DIR/github/kritis >/dev/null
    make integration-in-docker
popd

