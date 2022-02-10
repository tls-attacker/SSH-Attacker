package de.rub.nds.sshattacker.core.crypto.signature;

import de.rub.nds.sshattacker.core.exceptions.CryptoException;

public interface VerificationSignature {

    boolean verify(byte[] data, byte[] signatureBytes) throws CryptoException;

    SignatureAlgorithm getAlgorithm();
}
