#!/bin/bash

# Copyright (C) 2020 Synopsys, Inc.
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements. See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership. The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.

set -e

# Simple tests to verify the binary is functional
echo "VERSION"
synopsysctl --version 
echo "HELP"
synopsysctl --help > /dev/null

# Simple tests to verify each app can be created
echo "CREATE ALERT NATIVE"
synopsysctl create alert native alt -n alt --version 5.3.1 > /dev/null
echo "CREATE BDBA NATIVE"
synopsysctl create bdba native -n bdba --license-username user --license-password pass > /dev/null
echo "CREATE BLACKDUCK NATIVE"
synopsysctl create blackduck native bd -n bd --admin-password pass --user-password pass --persistent-storage=true -n mybd --seal-key abcdefghijklmnopqrstuvwxyz123456 --certificate-file-path mock-files/mock-tls.crt --certificate-key-file-path mock-files/mock-tls.key > /dev/null
echo "CREATE OPSSIGHT NATIVE"
synopsysctl create opssight native ops -n ops --version 2.2.5 > /dev/null
