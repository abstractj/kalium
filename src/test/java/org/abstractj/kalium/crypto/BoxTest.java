package org.abstractj.kalium.crypto;

import org.abstractj.kalium.encoders.Hex;
import org.abstractj.kalium.keys.PrivateKey;
import org.abstractj.kalium.keys.PublicKey;
import org.apache.commons.codec.binary.StringUtils;
import org.junit.Test;

public class BoxTest {

    String alicePrivate = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    String alicePublic = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    String bobPrivate = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    String bobPublic = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";

    @Test
    public void testEncrypt() throws Exception {

        Box box1 = new Box(bobPrivate, alicePublic);
        byte[] nonce1 = Random.randomBytes(24);
        byte[] value = box1.encrypt(nonce1, "sodium");

        Box box2 = new Box(alicePrivate, bobPublic);
        byte[] nonce2 = Random.randomBytes(24);
        byte[] data = box2.decrypt(nonce1, new String(value));

//        for (byte b : data) {
//            char c = (char)(((b&0x00FF)<<8) + (b&0x00FF));
//
//            System.out.println(c);
//        }
//
//        System.out.println("Shazam: " + Hex.decodeHex(StringUtils.newStringUsAscii(data)));

    }
}
