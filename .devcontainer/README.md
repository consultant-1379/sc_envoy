# Envoy Dev Container (experimental)

This directory contains some experimental tools for Envoy Development in [VSCode Remote - Containers](https://code.visualstudio.com/docs/remote/containers).

## Installing Visual Studio Code

- Type module avail vscode
- Type module add vscode/1.50.0 (or whichever version is the latest)
- Alternative to using VSC via the modules: Install the VSC package via snapd

In VSC:
- Do **not** install the recommended C++ extension
- Under "Extensions" install clangd (LLVM Extensions)
- Under "Extensions" install Remote - Containers [official guide](https://code.visualstudio.com/docs/remote/containers)

## How to use

The 2 files (Dockerfile, devcontainer.json) under devtools/envoy-builder/sc_envoy/.devcontainer are adapted to extract information from your env variables. All you need to do is export the following env var with your user id
```sh
echo -e "export USER_UID=\$(id -ua)" >> ~/.5g.devenv.profile

source ~/.5g.devenv.profile

```
- Dockerfile
- devcontainer.json

Note: in devcontainer.json, make sure that you set the correct path to the folder containing your 5g_proto folder under "workspaceMount"

After that, under "Open folder..." select the sc_envoy folder under /devtools/envoy-builder/
Note: If you already have an sc_envoy workspace in VSC, make sure that you first delete it by pressing F1 in VSC and typing "workspaces: delete", select the "Workspaces: Remove folder from workspaces..." and select the folder

After that, there should be a little pop-up window on the bottom right, offering an option to open that folder in a Container. Click on that option and now a container should be built using the Dockerfile and devcontainer.json files.

Now, in order to make Clangd work properly, you need to refresh the compilation database using the following script:
- tools/vscode/refresh_compdb.sh

This can be done by either using the Terminal on the bottom (which is a bash shell inside the deployed container) and running the script manually or by clickig on top on "Terminal -> Run Task... -> Refresh Compilation Database"
This will run partial build of Envoy and may take a while depends on the machine performance.
You should now notice that all warnings and errors from the code files disappear (or at least most of them). That is a sign that the compilation database was refreshed and Clangd is working correctly.

In the same terminal, also run these two commands to set your clang-toolchain's version and that you want to use clang (for the second, use the clang version that is installed under /llvm, the version shown in the example here is definitely outdated when you read this):

echo "build --config=clang" >> user.bazelrc
bazel/setup_clang.sh /llvm/clang+llvm-10.0.0-x86_64-linux-sles11.3

It would now be good to run the test script to check if the existing tests run through. This can be done by selectin on the top "Terminal -> Run Task... -> "Sepp Integration Test"

Finally, build the code and create a Static-Envoy binary by selecting "Terminal -> Run task... -> Build Envoy Static"
It is also possible to build and run tests remotely.

Note: Under .vscode/tasks.json, different build and execution tasks can be defined and then used under "Terminal -> Run task..."

If you have trouble compiling the code or refreshing comp_db because of a strange environment variable issues
then try renaming the .bazelrc file in /local/$user directory to .bazelrc_OLD 

### Disk performance

Docker for Mac/Windows is known to have disk performance issue, this makes formatting all files in the container very slow.
[Update the mount consistency to 'delegated'](https://code.visualstudio.com/docs/remote/containers-advanced#_update-the-mount-consistency-to-delegated-for-macos) is recommended.
