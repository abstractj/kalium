[![License](https://img.shields.io/:license-Apache2-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/org.abstractj.kalium/kalium/badge.svg)](https://maven-badges.herokuapp.com/maven-central/org.abstractj.kalium/kalium)
[![Build Status](https://travis-ci.org/abstractj/kalium.png?branch=master)](https://travis-ci.org/abstractj/kalium)
[![Build status](https://ci.appveyor.com/api/projects/status/github/abstractj/kalium?branch=master&svg=true)](https://ci.appveyor.com/project/abstractj/kalium/branch/master)
[![Say Thanks](https://img.shields.io/badge/Say%20Thanks-!-1EAEDB.svg)](https://saythanks.io/to/abstractj)

# kalium - Java binding to the Networking and Cryptography (NaCl) library

A Java binding to [Networking and Cryptography](http://nacl.cr.yp.to/) library by [Daniel J. Bernstein](http://cr.yp.to/djb.html). All the hard work of making a portable NaCl API version was done by [Frank Denis](https://github.com/jedisct1) on [libsodium](https://github.com/jedisct1/libsodium) and kalium was totally inspired by [Tony Arcieri's](https://github.com/tarcieri) work with [RbNaCl](https://github.com/cryptosphere/rbnacl).

## Requirements

* JDK 6 or [higher](http://www.oracle.com/technetwork/java/javase/downloads/index.html)
* [Apache Maven](http://maven.apache.org/guides/getting-started/)

## Installation

### libsodium

kalium is implemented using [jnr-ffi](https://github.com/jnr/jnr-ffi) to bind the shared libraries from [libsodium](https://github.com/jedisct1/libsodium). For a more detailed explanation, please refer to [RbNaCl's documentation](https://github.com/cryptosphere/rbnacl/blob/master/README.md).

#### OSX
OS X users can get libsodium via [homebrew](http://mxcl.github.com/homebrew/) with:

    brew install libsodium

#### Windows
Windows users will need to provide the pre-build binaries from `libsodium`.

- Download `libsodium` from https://download.libsodium.org/libsodium/releases/
- Choose the version of `libsodium` you wish to use
    - The archives follow the following pattern: libsodium-{version}-msvc.zip
- From the archive find the artifacts compiled for your architecture and then the MSVC tool set of your choice
    - For example: `v141 // these were compiled against the MSVC v141 (i.e. Visual Studio 2017)`
- Extract from the archive the `dll` library files into **one** of the following locations:
    - into the `lib` at the root of the working directory directory of your project.
    - into a location that is included in your `PATH` environment variable.

For example, on Windows 10 machine with a x64 architecture:
```
{archive root}
└───x64
    ...
    └───Release
        ...
        └───v141
            ...
            └───dynamic <- copy the library files from this locaiton.
```

### kalium installation

Add as a [Maven dependency](http://search.maven.org/#search%7Cgav%7C1%7Cg%3A%22org.abstractj.kalium%22%20AND%20a%3A%22kalium%22) to your project.

### FAQ

#### Is Android supported?
  No.

#### Would be nice to have some documentation. Do you have some?

  Look at the libsodium docs, they are self explanatory. Or, contribute with docs.

#### I'm experiencing some issues on Windows. Do you have any idea?

  I'm sorry but I'm completely clueless about Windows environment, but if you have any suggestions or PR changes. They will be more than welcome.

### Notes

Kalium is the effort of a **really** small group of people, feedback, bug reports and patches are always welcome.

