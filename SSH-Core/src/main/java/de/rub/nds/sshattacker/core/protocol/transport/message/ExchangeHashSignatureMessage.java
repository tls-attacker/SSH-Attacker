/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;

/**
 * A message containing the servers' signature computed over the exchange hash using the host key.
 */
public interface ExchangeHashSignatureMessage {

    ModifiableInteger getSignatureLength();

    void setSignatureLength(ModifiableInteger signatureLength);

    void setSignatureLength(int signatureLength);

    ModifiableByteArray getSignature();

    void setSignature(ModifiableByteArray signature);

    void setSignature(byte[] signature);

    void setSignature(ModifiableByteArray signature, boolean adjustLengthField);

    void setSignature(byte[] signature, boolean adjustLengthField);
}
