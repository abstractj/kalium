package org.abstractj.kalium.keys;

import static org.abstractj.kalium.NaCl.Sodium.*;
import static org.abstractj.kalium.NaCl.sodium;
import static org.abstractj.kalium.crypto.Util.*;

/**
 * per https://download.libsodium.org/doc/advanced/scalar_multiplication.html
 */
public class KeyAgreement {

    private byte[] publicKey;
    private byte[] privateKey;

    public KeyAgreement(byte[] privateKey) {
        checkLength(privateKey, CRYPTO_BOX_SECRETKEYBYTES);
        this.privateKey = privateKey;
        publicKey = zeros(CRYPTO_BOX_PUBLICKEYBYTES);
        isValid(sodium().crypto_scalarmult_base(publicKey, privateKey),
                "scalarmult failed");
    }

    public KeyAgreement(byte[] publicKey, byte[] privateKey) {
        checkLength(publicKey, CRYPTO_BOX_PUBLICKEYBYTES);
        checkLength(privateKey, CRYPTO_BOX_SECRETKEYBYTES);
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public byte[] sharedKeyClient(byte[] otherPublicKey) {
        return sharedKey(publicKey, otherPublicKey, q(otherPublicKey));
    }

    public byte[] sharedKeyServer(byte[] otherPublicKey) {
        return sharedKey(otherPublicKey, publicKey, q(otherPublicKey));
    }

    private byte[] q(byte[] p) {
        checkLength(p, CRYPTO_BOX_PUBLICKEYBYTES);
        byte[] q = zeros(CRYPTO_SCALARMULT_BYTES);
        isValid(sodium().crypto_scalarmult(q, privateKey, p),
                "key agreement failed");
        return q;
    }

    private byte[] sharedKey(byte[] pk1, byte[] pk2, byte[] q) {
        byte[] out = zeros(CRYPTO_GENERICHASH_BYTES);
        byte[] hstate = zeros(sodium().crypto_generichash_statebytes());

        isValid(sodium().crypto_generichash_init(
                        hstate, null, 0, CRYPTO_GENERICHASH_BYTES),
                "key agreement failed");
        isValid(sodium().crypto_generichash_update(
                        hstate, q, q.length),
                "key agreement failed");
        isValid(sodium().crypto_generichash_update(
                        hstate, pk1, pk1.length),
                "key agreement failed");
        isValid(sodium().crypto_generichash_update(
                        hstate, pk2, pk2.length),
                "key agreement failed");
        isValid(sodium().crypto_generichash_final(
                        hstate, out, CRYPTO_GENERICHASH_BYTES),
                "key agreement failed");

        return out;
    }
}
