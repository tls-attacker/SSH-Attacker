/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.NamedGroup;
import org.junit.jupiter.api.Test;

public class XCurveEcdhKeyExchangeTest {
    /*
     * Test vectors taken from RFC 7748 Section 6.1 (X25519) and 6.2 (X448)
     */
    /** Test of XCurveEcdhKeyExchange with X25519 being used as the named group */
    @Test
    public void testXCurveEcdhX25519() {
        byte[] privateKeyA =
                ArrayConverter.hexStringToByteArray(
                        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] expectedPublicKeyA =
                ArrayConverter.hexStringToByteArray(
                        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        byte[] privateKeyB =
                ArrayConverter.hexStringToByteArray(
                        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        byte[] expectedPublicKeyB =
                ArrayConverter.hexStringToByteArray(
                        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        byte[] expectedSharedSecret =
                ArrayConverter.hexStringToByteArray(
                        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        XCurveEcdhKeyExchange keyExchangeOnASite =
                new XCurveEcdhKeyExchange(NamedGroup.ECDH_X25519);
        XCurveEcdhKeyExchange keyExchangeOnBSite =
                new XCurveEcdhKeyExchange(NamedGroup.ECDH_X25519);
        keyExchangeOnASite.setLocalKeyPair(privateKeyA);
        keyExchangeOnBSite.setLocalKeyPair(privateKeyB);
        assertArrayEquals(
                expectedPublicKeyA, keyExchangeOnASite.getLocalKeyPair().getPublic().getEncoded());
        assertArrayEquals(
                expectedPublicKeyB, keyExchangeOnBSite.getLocalKeyPair().getPublic().getEncoded());

        keyExchangeOnASite.setRemotePublicKey(expectedPublicKeyB);
        keyExchangeOnBSite.setRemotePublicKey(expectedPublicKeyA);
        keyExchangeOnASite.computeSharedSecret();
        keyExchangeOnBSite.computeSharedSecret();

        assertTrue(keyExchangeOnASite.isComplete());
        assertTrue(keyExchangeOnBSite.isComplete());
        assertArrayEquals(expectedSharedSecret, keyExchangeOnASite.getSharedSecret().toByteArray());
        assertArrayEquals(expectedSharedSecret, keyExchangeOnBSite.getSharedSecret().toByteArray());
    }

    /** Test of XCurveEcdhKeyExchange with X448 being used as the named group */
    @Test
    public void testXCurveEcdhX448() {
        byte[] privateKeyA =
                ArrayConverter.hexStringToByteArray(
                        "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b");
        byte[] expectedPublicKeyA =
                ArrayConverter.hexStringToByteArray(
                        "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0");
        byte[] privateKeyB =
                ArrayConverter.hexStringToByteArray(
                        "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d");
        byte[] expectedPublicKeyB =
                ArrayConverter.hexStringToByteArray(
                        "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609");
        byte[] expectedSharedSecret =
                ArrayConverter.hexStringToByteArray(
                        "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d");

        XCurveEcdhKeyExchange keyExchangeOnASite = new XCurveEcdhKeyExchange(NamedGroup.ECDH_X448);
        XCurveEcdhKeyExchange keyExchangeOnBSite = new XCurveEcdhKeyExchange(NamedGroup.ECDH_X448);
        keyExchangeOnASite.setLocalKeyPair(privateKeyA);
        keyExchangeOnBSite.setLocalKeyPair(privateKeyB);
        assertArrayEquals(
                expectedPublicKeyA, keyExchangeOnASite.getLocalKeyPair().getPublic().getEncoded());
        assertArrayEquals(
                expectedPublicKeyB, keyExchangeOnBSite.getLocalKeyPair().getPublic().getEncoded());

        keyExchangeOnASite.setRemotePublicKey(expectedPublicKeyB);
        keyExchangeOnBSite.setRemotePublicKey(expectedPublicKeyA);
        keyExchangeOnASite.computeSharedSecret();
        keyExchangeOnBSite.computeSharedSecret();

        assertTrue(keyExchangeOnASite.isComplete());
        assertTrue(keyExchangeOnBSite.isComplete());
        assertArrayEquals(expectedSharedSecret, keyExchangeOnASite.getSharedSecret().toByteArray());
        assertArrayEquals(expectedSharedSecret, keyExchangeOnBSite.getSharedSecret().toByteArray());
    }
}
