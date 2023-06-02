/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.serializer;

import de.rub.nds.sshattacker.core.protocol.authentication.message.AuthenticationMessage;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessageSerializer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AuthenticationMessageSerializer
        extends ProtocolMessageSerializer<AuthenticationMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the ApplicationMessageSerializer
     *
     * @param message Message that should be serialized
     */
    public AuthenticationMessageSerializer(AuthenticationMessage message) {
        super(message);
    }

    @Override
    protected byte[] serializeBytes() {
        LOGGER.debug("Serializing ApplicationMessage");
        writeData();
        return getAlreadySerialized();
    }

    /** Writes the data of the ApplicationMessage into the final byte[] */
    private void writeData() {
        appendBytes(message.getData().getValue());
        LOGGER.debug("Data: {}", message.getData().getValue());
    }
}
