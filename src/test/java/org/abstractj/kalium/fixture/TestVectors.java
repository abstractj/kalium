package org.abstractj.kalium.fixture;

public class TestVectors {

    /**
     * SHA256 test vectors
     */

    public static final String SHA256_MESSAGE = "My Bonnie lies over the ocean, my Bonnie lies over the sea";
    public static final String SHA256_DIGEST = "d281d10296b7bde20df3f3f4a6d1bdb513f4aa4ccb0048c7b2f7f5786b4bcb77";
    public static final String SHA256_DIGEST_EMPTY_STRING = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /**
     * SHA512 test vectors
     */
    public static final String SHA512_MESSAGE = "My Bonnie lies over the ocean, Oh bring back my Bonnie to me";
    public static final String SHA512_DIGEST = "2823e0373001b5f3aa6db57d07bc588324917fc221dd27975613942d7f2e19bf4" +
            "44654c8b9f4f9cb908ef15f2304522e60e9ced3fdec66e34bc2afb52be6ad1c";
    public static final String SHA512_DIGEST_EMPTY_STRING = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921" +
            "d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";


    /**
     * Curve25519 test vectors
     */

    public static final String BOB_PRIVATE_KEY = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    public static final String BOB_PUBLIC_KEY = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";

    public static final String ALICE_PRIVATE_KEY = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    public static final String ALICE_PUBLIC_KEY = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    public static final String ALICE_MULT_BOB = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
}
