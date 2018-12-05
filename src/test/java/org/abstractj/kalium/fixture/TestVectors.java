/**
 * Copyright 2013 Bruno Oliveira, and individual contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.abstractj.kalium.fixture;

public class TestVectors {

    /**
     * HMAC SHA512256 test vectors
     */

    public static final String AUTH_KEY = "eea6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff880";
    public static final String AUTH_MESSAGE = "8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186a" +
            "c0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738" +
            "b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da" +
            "99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74" +
            "e355a5";
    public static final String AUTH_HMAC_SHA512256 = "b2a31b8d4e01afcab2ee545b5caf4e3d212a99d7b3a116a97cec8e83c32e107d";

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
     * Blake2 test vectors
     */

    public static final String Blake2_MESSAGE = "The quick brown fox jumps over the lazy dog";
    public static final String Blake2_DIGEST = "01718cec35cd3d796dd00020e0bfecb473ad23457d063b75eff29c0ffa2e58a9";
    public static final String Blake2_DIGEST_EMPTY_STRING = "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8";
    public static final String Blake2_KEY = "This is a super secret key. Ssshh!";
    public static final String Blake2_SALT = "0123456789abcdef";
    public static final String Blake2_PERSONAL = "fedcba9876543210";
    public static final String Blake2_DIGEST_WITH_SALT_PERSONAL = "108e81d0c7b0487de45c54554ea35b427f886b098d792497c6a803bbac7a5f7c";

    /**
     * SipHash-2-4 test vectors
     */

    public static final String SIPHASH24_KEY = "000102030405060708090a0b0c0d0e0f";
    public static final String SIPHASH24_MESSAGE = "000102030405060708090a0b0c0d0e";
    public static final String SIPHASH24_DIGEST = "e545be4961ca29a1";
    public static final String SIPHASH24_DIGEST_EMPTY_STRING = "310e0edd47db6f72";

    /**
     * pwhash test vectors
     * */
    
    public static final String PWHASH_MESSAGE = "Correct Horse Battery Staple";
    public static final String PWHASH_SALT = "[<~A 32-bytes salt for scrypt~>]";
    public static final String PWHASH_DIGEST = "a2ec8a8ee744e0ff2c26d4fc198ddf7c0cd1460b5b6729e0d8518b6577c69acd412491f0913737e64c5c9136c04731545e756e0a9be35f55337e446c6bbc3a3f";
    public static final String PWHASH_DIGEST_EMPTY_STRING = "f8b1543b940c7898ce90261d07f5193cb0570081e47b01610c043b8091666e12585ab9844edb189624c2ba662ca7478cfbed9f38fe1066b7ce583a3321470424";
    
    
    /**
     * Curve25519 test vectors
     */

    public static final String BOB_PRIVATE_KEY = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    public static final String BOB_PUBLIC_KEY = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";

    public static final String ALICE_PRIVATE_KEY = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    public static final String ALICE_PUBLIC_KEY = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    public static final String ALICE_MULT_BOB = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

    public static final String BOX_NONCE = "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37";
    public static final String BOX_MESSAGE = "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffc" +
            "e5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb31" +
            "0e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde" +
            "048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f93776384864" +
            "5e0705";
    public static final String BOX_CIPHERTEXT = "f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce" +
            "48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c972" +
            "71d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae" +
            "90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b3" +
            "7973f622a43d14a6599b1f654cb45a74e355a5";

    public static final String SECRET_KEY = "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389";

    public static final String SIGN_PRIVATE = "b18e1d0045995ec3d010c387ccfeb984d783af8fbb0f40fa7db126d889f6dadd";
    public static final String SIGN_PRIVATE_CURVE25519 = "38e5cdf33bc9e13086f58a3fea86d574e85e7865cffa5e8c9335f200a41d036c";
    public static final String SIGN_MESSAGE = "916c7d1d268fc0e77c1bef238432573c39be577bbea0998936add2b50a653171" +
            "ce18a542b0b7f96c1691a3be6031522894a8634183eda38798a0c5d5d79fbd01" +
            "dd04a8646d71873b77b221998a81922d8105f892316369d5224c9983372d2313" +
            "c6b1f4556ea26ba49d46e8b561e0fc76633ac9766e68e21fba7edca93c4c7460" +
            "376d7f3ac22ff372c18f613f2ae2e856af40";
    public static final String SIGN_SIGNATURE = "6bd710a368c1249923fc7a1610747403040f0cc30815a00f9ff548a896bbda0b" +
            "4eb2ca19ebcf917f0f34200a9edbad3901b64ab09cc5ef7b9bcc3c40c0ff7509";
    public static final String SIGN_PUBLIC = "77f48b59caeda77751ed138b0ec667ff50f8768c25d48309a8f386a2bad187fb";
    public static final String SIGN_PUBLIC_CURVE25519 = "35488a98f7ec26ae27099809afb27587b198b1197b5bcb0dec41153db2bf9952";


    /**
     * AEAD test vectors
     */

    public static final String AEAD_KEY = "4290bcb154173531f314af57f3be3b5006da371ece272afa1b5dbdd1100a1007";
    public static final String AEAD_MESSAGE = "86d09974840bded2a5ca";
    public static final String AEAD_NONCE = "cd7cf67be39c794a";
    public static final String AEAD_AD = "87e229d4500845a079c0";
    public static final String AEAD_CT = "e3e446f7ede9a19b62a4677dabf4e3d24b876bb284753896e1d6";
}
