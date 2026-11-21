# Reproducing the upstream checks on macOS

Use the upstream commit specified in the main README. This harness generates
fictitious databases at test time using the official core; no upstream fixtures
are copied into this project.

With Xcode and `wx-config` from wxWidgets installed, run from PSafeKit:

```bash
ref="$(mktemp -d)/pwsafe"
git clone https://github.com/pwsafe/pwsafe.git "$ref"
git -C "$ref" checkout --detach 5302acb15b1b598898302261ab2fa669a550a869
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
(
  cd "$ref"
  Xcode/generate-configs -r "$(command -v wx-config)" > Xcode/pwsafe-release.xcconfig
  xcodebuild -project Xcode/pwsafe-xcode6.xcodeproj -target os -target core \
    -configuration Release SYMROOT="$ref/products" OBJROOT="$ref/objects" \
    CODE_SIGNING_ALLOWED=NO MACOSX_DEPLOYMENT_TARGET=13.0 \
    GCC_TREAT_WARNINGS_AS_ERRORS=NO \
    'WARNING_CFLAGS=$(inherited) -Wno-error=deprecated-declarations' \
    'GCC_PREPROCESSOR_DEFINITIONS=$(inherited) NO_YUBI' \
    'EXCLUDED_SOURCE_FILE_NAMES=*Yubi*'
)
xcrun clang++ -std=c++17 -DUNICODE -DNO_YUBI \
  -I"$ref/src" -I"$ref/src/os" -I"$ref/src/core" $(wx-config --cxxflags) \
  Tests/Interop/upstream-fixture.cpp \
  "$ref/products/Release/libcore.a" "$ref/products/Release/libos.a" \
  $(wx-config --libs) -framework CoreServices -framework Security \
  -o "$ref/upstream-fixture"
PSAFEKIT_UPSTREAM_FIXTURE="$ref/upstream-fixture" swift test
```
