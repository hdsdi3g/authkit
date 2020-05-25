#!/bin/sh
# Usage: <no parameter>
# You will need "mvn" and "git" commands
#
# This file is part of AuthKit.
# Licencied under LGPL v3.
# Copyright (C) hdsdi3g for hd3g.tv 2019

BASE_DIR=$(git rev-parse --show-toplevel);

cd $BASE_DIR

echo "This utility let can you create a security admin, or update it's password";
echo "Please, before continue, check if the database configuration is set and the database scheme is already setup."
echo "Also check before continue if the configuration have security keys set (like jwt_secret and cipher_secret)";
echo "";
echo "You can create security admin accounts as much as you want.";
echo "";
read -p "Press [ENTER] to continue " nothing

read -p "Enter the security admin login name to create/update: " loginname
if [ -z "$loginname" ]
then
      echo "Cancel operation."
      exit;
fi

read -s -p "Enter the password: " password1; echo
if [ -z "$password1" ]
then
      echo "Cancel operation."
      exit;
fi

read -s -p "Re-enter the password: " password2; echo
if [ -z "$password2" ]
then
      echo "Cancel operation."
      exit;
fi

OPTS="";
if [ -d "src/main/java/tv/hd3g/authkit" ]; then
	# This run from original authkit dir; this run in a test mode.
	OPTS="$OPTS -Dspring-boot.run.folders=src/test/resources";
fi

if [ "$password1" == "$password2" ]; then
	export AUTHKIT_NEWADMIN=$loginname
	export AUTHKIT_PASSWORD=$password1
	echo "Start java application, please standby..."
	echo ""
	mvn spring-boot:run -q $OPTS -Dspring-boot.run.arguments="create-security-admin"
else
    echo "Passwords are not equal, cancel operation."
fi
