package de.rub.nds.sshattacker.core.crypto.signature;

import de.rub.nds.sshattacker.core.exceptions.CryptoException;

public interface SigningSignature {

    byte[] sign(byte[] data) throws CryptoException;

    SignatureAlgorithm getAlgorithm();
}
