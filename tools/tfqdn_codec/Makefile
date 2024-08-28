# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# !!!!! Run this on the VDI, not inside an Envoy build-container!!!!!!
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

# This is because inside the build container we have a much newer glibc than
# on the VDI, and the binary wouldn't run.
# Static linking inside the build container is not possible because it doesn't
# have static libc.a and libm.a
#
CXX:=/app/vbuild/RHEL7-x86_64/clang/12.0.1/bin/clang++

tfqdn_codec: tfqdn_codec.cc ../../source/extensions/filters/http/eric_proxy/tfqdn_codec.h ../../source/extensions/filters/http/eric_proxy/tfqdn_codec.cc
	${CXX} -o tfqdn_codec --std=c++17 -I../../ tfqdn_codec.cc -static

clean:
	rm -f tfqdn_codec

install:
	cp -f tfqdn_codec /proj/sc-tools/bin/
