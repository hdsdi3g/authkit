#!/bin/sh
# Usage: <no parameter>
# You will need "mvn" and "git" commands
#
# This file is part of SelfAutoRESTDoc.
# Licencied under LGPL v3.
# Copyright (C) hdsdi3g for hd3g.tv 2019

BASE_DIR=$(git rev-parse --show-toplevel);

cd $BASE_DIR

echo "This utility make the API.md document";

if [ ! -d "src/main/java" ]; then
	echo "Please run-it on from a project repository";
	exit 1;
fi

echo "Start java application, please standby..."
echo ""
mvn spring-boot:run -Dspring.main.banner-mode=off -Dserver.port=0 -Dspring-boot.run.arguments="export-rest-doc-api"
