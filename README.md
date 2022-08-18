# [Stream Security](https://ahfakt.github.io/StreamSecurity/)

```shell
# Target system processor
SYSTEM_PROCESSOR=x86_64

# Debug, Release, RelWithDebInfo, MinSizeRel ...
BUILD_TYPE=Debug

# Shared library files will be in ${INSTALL_PREFIX}/lib/${SYSTEM_PROCESSOR}/${BUILD_TYPE}
INSTALL_PREFIX=/home/user

# Uncomment to generate Doxygen documentation target
#DOC_ROOT=/home/user/doc

# cmake --help to see available generators
GENERATOR="Unix Makefiles"

git clone https://github.com/ahfakt/Stream.git
git clone https://github.com/ahfakt/StreamSecurity.git

# Generate
mkdir build
cd StreamSecurity
cmake \
    -B ../build/StreamSecurity/${SYSTEM_PROCESSOR}/${BUILD_TYPE} \
    -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
    -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} \
    -DDOC_ROOT=${DOC_ROOT} \
    -DCMAKE_DEPENDS_USE_COMPILER=FALSE \
    -G "${GENERATOR}"

# Build
# Stream | StreamOBJ | StreamDoc
# StreamSecurity | StreamSecurityOBJ | StreamSecurityDoc
# Test targets are avaiable only when BUILD_TYPE=Debug
cmake \
    --build ../build/StreamSecurity/${SYSTEM_PROCESSOR}/${BUILD_TYPE} \
    --target StreamSecurity \
    -- -j 6
```