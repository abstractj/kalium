package org.abstractj.kalium.crypto;

import org.abstractj.kalium.NaCl.Sodium;
import org.abstractj.kalium.encoders.Hex;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.StringUtils;

import static org.abstractj.kalium.NaCl.SODIUM_INSTANCE;
import static org.abstractj.kalium.NaCl.Sodium.SCALAR_BYTES;

public class Point {

    private static final Sodium sodium = SODIUM_INSTANCE;

    private final byte[] point;
    private byte[] result;

    public Point(String point) {
        this.point =  Hex.decodeHexString(point);
    }

    public Point mult(String n) throws DecoderException {
        byte[] intValue = Hex.decodeHexString(n);
        result = Util.zeros(SCALAR_BYTES);
        sodium.crypto_scalarmult_curve25519_ref(result, intValue, point);
        return this;
    }

    public String toHex() {
        return Hex.encodeHexString(result);
    }
}
