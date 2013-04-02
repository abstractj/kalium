# kalium - Java binding to the Networking and Cryptography (NaCl) library 

A Java binding to [Networking and Cryptography](http://nacl.cr.yp.to/) library by [Daniel J. Bernstein](http://cr.yp.to/djb.html). All the hard work of making a portable NaCl API version was done by [Frank Denis](https://github.com/jedisct1) on [libsodium](https://github.com/jedisct1/libsodium) and kalium was totally inspired by [Tony Arcieri's](https://github.com/tarcieri) work with [RbNaCl](https://github.com/cryptosphere/rbnacl).   

## Requirements

* JDK 6 or [higher](http://www.oracle.com/technetwork/java/javase/downloads/index.html)
* [Apache Maven](http://maven.apache.org/guides/getting-started/)

## Installation

### libsodium

kalium is implemented using [jnr-ffi](https://github.com/jnr/jnr-ffi) to bind the shared libraries from [libsodium](https://github.com/jedisct1/libsodium). For a more detailed explanation, please refer to [RbNaCl's documentation](https://github.com/cryptosphere/rbnacl/blob/master/README.md).

OS X users can get libsodium via [homebrew](http://mxcl.github.com/homebrew/) with: 

    brew install libsodium 

### kalium installation

    git clone https://github.com/abstractj/kalium && cd kalium
    mvn clean install
    
Add as a Maven dependency at your project:

    <dependency>
        <groupId>org.abstractj.kalium</groupId>
        <artifactId>kalium</artifactId>
        <version>0.1.3-SNAPSHOT</version>
        <scope>compile</scope>
    </dependency>
        
    
### Notes

kalium is a work in progress, feedback, bug reports and patches are always welcome.



 
