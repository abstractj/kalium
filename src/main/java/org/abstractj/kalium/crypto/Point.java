package org.abstractj.kalium.crypto;

import org.abstractj.kalium.NaCl.Sodium;
import org.abstractj.kalium.encoders.Hex;
import org.apache.commons.codec.DecoderException;

import static org.abstractj.kalium.NaCl.SODIUM_INSTANCE;
import static org.abstractj.kalium.NaCl.Sodium.SCALAR_BYTES;

public class Point {

    private static final Sodium sodium = SODIUM_INSTANCE;
    private static final String STANDARD_GROUP_ELEMENT = "0900000000000000000000000000000000000000000000000000000000000000";

    private byte[] point;
    private byte[] result;

    public Point() {
        this.point = Hex.decodeHexString(STANDARD_GROUP_ELEMENT);
    }

    public Point(String point) {
        this.point = Hex.decodeHexString(point);
    }

    public Point mult(String n) throws DecoderException {
        byte[] intValue = Hex.decodeHexString(n);
        result = Util.zeros(SCALAR_BYTES);
        sodium.crypto_scalarmult_curve25519_ref(result, intValue, point);
        return this;
    }

    public String value() {
        return Hex.encodeHexString(result);
    }

    public String toHex() {
        return Hex.encodeHexString(point);
    }

    public byte[] toBytes() {
        return point;
    }
}
