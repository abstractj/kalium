package org.abstractj.kalium.keys;

import org.junit.Test;

import static org.abstractj.kalium.encoders.Encoder.HEX;
import static org.abstractj.kalium.fixture.TestVectors.*;
import static org.junit.Assert.assertArrayEquals;

public class KeyAgreementTest {

    @Test
    public void testAgreement() throws Exception {
        KeyAgreement clientAgreement = new KeyAgreement(
                HEX.decode(ALICE_PRIVATE_KEY));
        KeyAgreement serverAgreement = new KeyAgreement(
                HEX.decode(BOB_PRIVATE_KEY));

        assertArrayEquals(
                clientAgreement.sharedKeyClient(HEX.decode(BOB_PUBLIC_KEY)),
                serverAgreement.sharedKeyServer(HEX.decode(ALICE_PUBLIC_KEY)));
    }
}
