#! /bin/bash
# -----------------------------------------------------------------------------
# Copyright (C) 2022 Excelfore Corporation. All Rights Reserved.
#
# Get the project version from the latest tag
# For now we will be using the tag prefix 'eSync-client-SDK-'
#
# Currently, multiple tag is used on one commit, which needs to be improved.
# The 'git describe' command, by default, will get the latest tag (based on
# timestamp) that matches the prefix/pattern provided.
# -----------------------------------------------------------------------------
PREFIX="eSync-client-SDK-"
DESCRIBE=`git describe --tags --dirty --match "${PREFIX}[0-9].*"`

# Remove prefix from tag information
VERSION=${DESCRIBE#$PREFIX}

# Get Major/Minor/Patch/Tweak value of the Tag
MAJOR=`echo $VERSION | awk '{split($0,a,"."); print a[1]}'`
MINOR=`echo $VERSION | awk '{split($0,a,"."); print a[2]}'`
PATCH=`echo $VERSION | awk '{split($0,a,"."); print a[3]}'`

# For the TWEAK version we will get the number of commit after the latest
# matched tag
TWEAK=`echo $VERSION | awk '{split($0,a,"-"); print a[2]}'`

echo -n "${MAJOR}.${MINOR}.${PATCH}.${TWEAK}"
