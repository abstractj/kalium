package org.abstractj.kalium.crypto;

import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_STREAM_KEYBYTES;
import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_STREAM_NONCEBYTES;
import static org.abstractj.kalium.NaCl.sodium;
import static org.abstractj.kalium.crypto.Util.checkLength;

/**
 * Created by yi on 02/03/2017.
 */
public class Advanced {

    public byte[] crypto_stream_xsalsa20_xor(byte[] message, byte[] nonce, byte[] key) {

        checkLength(nonce, CRYPTO_STREAM_NONCEBYTES);
        checkLength(key, CRYPTO_STREAM_KEYBYTES);
        byte[] buffer = new byte[message.length];
        sodium().crypto_stream_xor(buffer, message, message.length, nonce, key);
        return buffer;

    }
}
