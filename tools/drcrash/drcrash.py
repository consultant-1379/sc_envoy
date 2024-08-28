#!/bin/env python3
#
# Analyze an Envoy core dump
# eedala 2022-05-21

from collections import Counter
from subprocess import run
import argparse
import os
import re
import sys
import tempfile

def findGitCommitIdFromCoredump(filename):
    """Find and return the GIT commit hash/sha in the core-file
    or an empty string if not found"""
    sha = findGitCommitIdFromCoredumpMethod2(filename)
    if len(sha) > 0:
        return sha

    sha = findGitCommitIdFromCoredumpMethod1(filename)
    if len(sha) > 0:
        return sha

    return ''

def findGitCommitIdFromCoredumpMethod1(filename):
    out = os.popen('strings ' + filename + ' | grep -A1 revision.sha').read()
    candidates = Counter()
    for line in out.split('\n'):
        # Find a line that could be a SHA:
        match = re.search(r'([0-9a-fA-F]{40})', line)
        if match:
            candidates[match.group(1)] += 1

    # We take the most common candidate (in case there are false matches -- the
    # commit SHA appears more than once
    most_common = candidates.most_common(1)
    if len(most_common) > 0:
        return candidates.most_common(1)[0][0]
    else:
        return ""

def findGitCommitIdFromCoredumpMethod2(filename):
    out = os.popen('strings ' + filename + ' | grep "/RELEASE/"').read()
    if len(out) > 0:
        return out.split('/')[0]
    else:
        return ''

def findGitTagsForCommitId(sha):
    """Given a GIT commit ID/SHA, return the tag(s) for the commit.
    If the commit is not tagged, find the next older commit that
    has a tag and return that. It is possible to get multiple tags,
    comma-separated"""
    # When "git log" is piped, no tags will be shown -> add --decorate
    out = os.popen('git log --decorate=short').read()
    state = "search sha"
    print(f"Searching GIT tag for commit {sha}")
    for line in out.split("\n"):
        if state == "search sha":
            if sha in line:
                match = re.search(r'[0-9a-fA-F] \(tag: ([^)]+)', line)
                if match:
                        return match.group(1)
                else:
                        # The line with the sha doesn't contain a tag, find the
                        # next older commit that does
                        print("Commit found, but no tag, finding next older commit with a tag")
                        state = "search next older commit"
        if state == "search next older commit":
            if 'tag' in line:
                match = re.search(r'[0-9a-fA-F] \(tag: ([^)]+)', line)
                if match:
                        return match.group(1)
    return ""


def runImageInDebugger(tags, corefile, shell_commands, gdb_commands):
    """Given a string with one or more comma-separated GIT tags, use
    the first tag to pull the corresponding docker image from armdocker
    and run it. Inside the container, the supplied commands are executed
    as the entrypoint"""
    taglist = tags.split(", ")
    tag = taglist[0]
    # In armdocker, it's just the numbers
    tag = tag.replace("envoy-v", "")
    if len(taglist) > 1:
        print(f"More than one tag given, using first one ({tag})")
    # Prepare the entrypoint temporary file:
    entrypoint_filename = createAndFillTempFile(shell_commands, 0o755)
    # Prepare the commands for gdb:
    gdb_cmd_filename = createAndFillTempFile(gdb_commands)
    # The corefile has to be executable:
    os.chmod(corefile, 0x755)
    abscorefile = f"{os.getcwd()}/{corefile}"
    cmd = (f"docker run -it --rm --name envoy-core-dump --cap-add=SYS_PTRACE "
    f" --security-opt seccomp=unconfined "
    f" --mount type=bind,source={abscorefile},target=/core "
    f" --mount type=bind,source={entrypoint_filename},target=/entry.sh "
    f" --mount type=bind,source={gdb_cmd_filename},target=/root/.config/gdb/gdbinit "
    f" armdocker.rnd.ericsson.se/proj-5g-bsf/envoy/eric-scp-envoy-base-debug:{tag} bash /entry.sh")

    print("\nGoing to start the debug image with this command:")
    print(cmd)
    print("\nInside the container, run these commands:")
    print(shell_commands)
    print("Initialize gdb with these commands:")
    print(gdb_commands)
    print("Unpacking files and starting gdb... (can take a moment)\n")
    run(cmd, shell=True)
    os.remove(entrypoint_filename)

def createAndFillTempFile(content, mode=0o644):
    """Create a temporary file with the given content and
    permissions.  Then return its filename. The caller is
    responsible to delete the file when it's not needed
    any longer."""
    tmpf = tempfile.mkstemp()
    filename = tmpf[1]
    file = open(filename, "w")
    file.write(content)
    file.close()
    os.chmod(filename, mode)
    return filename



# Main program
parser = argparse.ArgumentParser()
parser.add_argument("corefile");
parser.add_argument("-s", "--stacktrace", help="Print stacktrace and exit", action='store_true', default=True)
parser.add_argument("-d", "--debugger", help="Load coredump into debugger and you continue", action='store_true')
parser.add_argument("-t", "--tag", help="Use this tag for the release instead of finding it from the coredump")
args = parser.parse_args()


print(f"Reading coredump from '{args.corefile}'")

if args.tag:
    tag = args.tag
else:
    sha = findGitCommitIdFromCoredump(args.corefile)
    print(f"Commit SHA is: {sha}")
    tag = findGitTagsForCommitId(sha)

print(f"Git tag is/are: {tag}")
if len(tag) == 0:
    sys.exit("No GIT tag found/available, exiting.\n-> Perhaps try again on a release branch?")


if args.debugger:
# Start the debugger with corefile, let user type commands:
    start_gdb_commands = ("tar xzf envoy_source.tgz\n"
    "tar xzf envoy_dwo.tgz\n"
    "mv -f */execroot/envoy/bazel-out .\n"
    "gdb /usr/local/bin/envoy core\n")
    gdb_init_commands = ("")
    runImageInDebugger(tag, args.corefile, start_gdb_commands, gdb_init_commands)
    sys.exit()

if args.stacktrace:
    # Print stacktrace and exit
    print_stacktrace_commands = ("tar xzf envoy_source.tgz\n"
    "tar xzf envoy_dwo.tgz\n"
    "mv -f */execroot/envoy/bazel-out .\n"
    "gdb /usr/local/bin/envoy -ex \"where -full\" -ex \"quit\" core\n"
    "echo exit\n")
    gdb_init_commands = ("set pagination off\n")
    runImageInDebugger(tag, args.corefile, print_stacktrace_commands, gdb_init_commands)
    sys.exit()

