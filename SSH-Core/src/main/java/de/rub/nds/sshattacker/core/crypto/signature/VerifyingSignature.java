/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.signature;

import de.rub.nds.sshattacker.core.constants.PublicKeyAlgorithm;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;

public interface VerifyingSignature {

    boolean verify(byte[] data, byte[] signatureBytes) throws CryptoException;

    PublicKeyAlgorithm getAlgorithm();
}
