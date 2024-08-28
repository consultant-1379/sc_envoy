How to fix refresh_compdb.sh failures (i.e. clang in VSC) for python version < 3.8:

Replace the files in this folder with the following:

python38_fix/repository_locations.bzl -> bazel/repository_locations.bzl

python38_fix/testing/requirements.txt -> tools/testing/requirements.txt

python38_fix/code_format/requirements.txt -> tools/code_format/requirements.txt


