package org.abstractj.kalium.keys;

import org.abstractj.kalium.util.Hex;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;

import static org.abstractj.kalium.NaCl.SODIUM_INSTANCE;
import static org.abstractj.kalium.NaCl.Sodium;

public class PrivateKey {

    private static final Sodium sodium = SODIUM_INSTANCE;

    public static final int PUBLICKEY_BYTES = 32;
    public static final int SECRETKEY_BYTES = 32;

    public static String generate() throws UnsupportedEncodingException {
        byte[] pk = new byte[PUBLICKEY_BYTES];
        byte[] sk = new byte[SECRETKEY_BYTES];
        sodium.crypto_box_curve25519xsalsa20poly1305_ref_keypair(pk, sk);
        encode(sk);
        return Hex.encodeHexString(sk);
    }

    public static void encode(byte[] decode) {

        Charset charset = Charset.forName("ISO-8859-1");
        CharsetDecoder decoder = charset.newDecoder();
        try {
            CharBuffer cbuf = decoder.decode(ByteBuffer.wrap(decode));
            String s = cbuf.toString();
            System.out.println(s);
        } catch (CharacterCodingException e) {
        }
    }

}
