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

import java.security.Key;

/**
 * An abstract extension class to the JavaSignature class implementing signature packing and
 * unpacking. This can be used in cases where the JavaSignature does not return the signature in the
 * required format. Processing of the signature is done by the unpackSignature() and packSignature()
 * abstract functions.
 */
public abstract class UnpackedJavaSignature extends JavaSignature {

    public UnpackedJavaSignature(PublicKeyAlgorithm algorithm, Key key) {
        super(algorithm, key);
    }

    @Override
    public boolean verify(byte[] data, byte[] signatureBytes) throws CryptoException {
        return super.verify(data, packSignature(signatureBytes));
    }

    @Override
    public byte[] sign(byte[] data) throws CryptoException {
        return unpackSignature(super.sign(data));
    }

    protected abstract byte[] unpackSignature(byte[] packedSignature);

    protected abstract byte[] packSignature(byte[] unpackedSignature);
}
