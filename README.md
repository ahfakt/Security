# [Stream Security](https://ahfakt.github.io/StreamSecurity/)

```shell
# Target system processor
SYSTEM_PROCESSOR=x64

# Debug, Release, RelWithDebInfo, MinSizeRel
BUILD_TYPE=Release

git clone https://github.com/ahfakt/Stream.git
git clone https://github.com/ahfakt/StreamSecurity.git

# Generate
mkdir build && cd StreamSecurity
cmake \
    -B../build/${SYSTEM_PROCESSOR}/${BUILD_TYPE}/StreamSecurity \
    -DCMAKE_BUILD_TYPE:STRING=${BUILD_TYPE} \
    -DCMAKE_CXX_STANDARD:STRING=20 \
    -G "Unix Makefiles"

# Build
# Stream | StreamDoc
# StreamSecurity | StreamSecurityDoc
# Test targets are avaiable only when BUILD_TYPE=Debug
# Documentation is avaiable only when BUILD_TYPE=Release
cmake \
    --build ../build/${SYSTEM_PROCESSOR}/${BUILD_TYPE}/StreamSecurity \
    --config ${BUILD_TYPE} \
    --target all
```