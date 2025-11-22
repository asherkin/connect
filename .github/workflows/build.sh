#!/bin/bash

cd "$(dirname $0)/../.."

if [[ $OS == Linux* ]]; then
	$CC --version
	$CXX --version

	apt install -y python3-pip

	# buildbot/generate_header.py is ran by ambuild and we want git to not fail due to user-perms (because docker)
	git config --global --add safe.directory $PWD

	pushd "$CACHE_PATH"
	python -m pip install ./ambuild
	popd
fi

mkdir build
cd build
python ../configure.py --enable-auto-versioning --enable-optimize --sdks="$SDKS" --mms-path="$CACHE_PATH/metamod-source" --hl2sdk-root="$CACHE_PATH" --sm-path="$CACHE_PATH/sourcemod"
ambuild
