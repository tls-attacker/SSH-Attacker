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
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;

/** A message containing the host key of the server. */
public interface HostKeyMessage {

    ModifiableInteger getHostKeyBytesLength();

    void setHostKeyBytesLength(ModifiableInteger hostKeyBytesLength);

    void setHostKeyBytesLength(int hostKeyBytesLength);

    ModifiableByteArray getHostKeyBytes();

    SshPublicKey<?, ?> getHostKey();

    void setHostKeyBytes(ModifiableByteArray hostKeyBytes);

    void setHostKeyBytes(byte[] hostKeyBytes);

    void setHostKeyBytes(ModifiableByteArray hostKeyBytes, boolean adjustLengthField);

    void setHostKeyBytes(byte[] hostKeyBytes, boolean adjustLengthField);

    void setSoftlyHostKeyBytes(byte[] hostKeyBytes, boolean adjustLengthField, Config config);
}
