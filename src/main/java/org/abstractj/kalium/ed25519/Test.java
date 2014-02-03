package org.abstractj.kalium.ed25519;

/**
 * Created by abstractj on 2/3/14.
 */

import org.abstractj.kalium.keys.VerifyKey;

import static org.abstractj.kalium.encoders.Hex.HEX;

/* Written by k3d3
 * Released to the public domain
 */

public class Test {

    public static void main(String[] args) {


        final String SIGN_PRIVATE = "b18e1d0045995ec3d010c387ccfeb984d783af8fbb0f40fa7db126d889f6dadd";
        final String SIGN_MESSAGE = "916c7d1d268fc0e77c1bef238432573c39be577bbea0998936add2b50a653171" +
                "ce18a542b0b7f96c1691a3be6031522894a8634183eda38798a0c5d5d79fbd01" +
                "dd04a8646d71873b77b221998a81922d8105f892316369d5224c9983372d2313" +
                "c6b1f4556ea26ba49d46e8b561e0fc76633ac9766e68e21fba7edca93c4c7460" +
                "376d7f3ac22ff372c18f613f2ae2e856af40";

        byte[] privateKey = HEX.decode(SIGN_PRIVATE);
        byte[] publicKey = Signature.publickey(privateKey);
        byte[] message = HEX.decode(SIGN_MESSAGE);
        byte[] signature = Signature.signature(message, privateKey, publicKey);
        try {
            System.out.println("check signature result:\n" + Signature.checkvalid(signature, message, publicKey));
        } catch (Exception e) {
            e.printStackTrace();
        }

        VerifyKey verifyKey = new VerifyKey(publicKey);
        System.out.println("True? " + verifyKey.verify(message, signature));
    }

}
