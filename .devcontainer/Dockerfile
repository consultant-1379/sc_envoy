FROM armdocker.rnd.ericsson.se/proj-5g-bsf/envoybuilder:3.0.0-20

ARG USER_UID
ARG USERNAME
ARG USER_GID=$USER_UID
# Set the llvm/clang version that you need, otherwise it should be the newest one
ARG LLVM_VERSION='/llvm/12.0.0'

ENV BUILD_DIR=/workspace/5g_proto/devtools/envoy-builder/sc_envoy/build
ENV ENVOY_STDLIB=libstdc++
ENV HOME=/local/$USERNAME
ENV LLVM_PREFIX=$LLVM_VERSION

RUN zypper refresh \
  && zypper install -y sudo gdb net-tools psmisc vim 2>&1 \
#  && groupadd -g 64000 eusers \
  && useradd -M -g 64000 -u $USER_UID $USERNAME \
  && echo "root:root" | chpasswd

ENV PATH=/bazelisk/latest:$LLVM_VERSION/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV CC=$LLVM_VERSION/bin/clang
ENV CXX=$LLVM_VERSION/bin/clang

ENV CLANG_FORMAT=$LLVM_VERSION/bin/clang-format
ENV CLANGD=$LLVM_VERSION/bin/clangd
ENV CLANG=$LLVM_VERSION/bin/clang
ENV ENVOY_BAZEL_OUTPUT_DIR=.bazel/output/

CMD sleep infinity