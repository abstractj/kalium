package org.abstractj.kalium.crypto;

import static org.abstractj.kalium.NaCl.Sodium.PWHASH_SCRYPTSALSA208SHA256_OUTBYTES;
import static org.abstractj.kalium.NaCl.Sodium.PWHASH_SCRYPTSALSA208SHA256_STRBYTES;
import static org.abstractj.kalium.NaCl.sodium;
import org.abstractj.kalium.encoders.Encoder;

public class Password {

    public Password() {
    }

    public String hash(byte[] passwd, Encoder encoder, byte[] salt, int opslimit, long memlimit) {
        return hash(PWHASH_SCRYPTSALSA208SHA256_OUTBYTES, passwd, encoder, salt, opslimit, memlimit);
    }

    public String hash(int length, byte[] passwd, Encoder encoder, byte[] salt, int opslimit, long memlimit) {
        byte[] buffer = new byte[length];
        sodium().crypto_pwhash_scryptsalsa208sha256(buffer, buffer.length, passwd, passwd.length, salt, opslimit, memlimit);
        return encoder.encode(buffer);
    }

    public String hash(byte[] passwd, Encoder encoder, int opslimit, long memlimit) {
        byte[] buffer = new byte[PWHASH_SCRYPTSALSA208SHA256_STRBYTES];
        sodium().crypto_pwhash_scryptsalsa208sha256_str(buffer, passwd, passwd.length, opslimit, memlimit);
        return encoder.encode(buffer);
    }

    public boolean verify(byte[] hashed_passwd, byte[] passwd) {
        int result = sodium().crypto_pwhash_scryptsalsa208sha256_str_verify(hashed_passwd, passwd, passwd.length);
        return result == 0;
    }
}