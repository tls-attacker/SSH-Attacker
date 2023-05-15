/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangePubkeyMessage;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RsaKeyExchangePubkeyMessageSerializer
        extends SshMessageSerializer<RsaKeyExchangePubkeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RsaKeyExchangePubkeyMessageSerializer(RsaKeyExchangePubkeyMessage message) {
        super(message);
    }

    public void serializeHostKeyBytes() {
        LOGGER.debug("Host key bytes length: {}", message.getHostKeyBytesLength().getValue());
        appendInt(
                message.getHostKeyBytesLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Host key bytes: {}", message.getHostKeyBytes());
        appendBytes(message.getHostKeyBytes().getValue());
    }

    public void serializeTransientPublicKey() {
        LOGGER.debug("Transient public key length: {}", message.getTransientPublicKeyBytesLength());
        appendInt(
                message.getTransientPublicKeyBytesLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Transient public key: {}", message.getTransientPublicKeyBytes());
        appendBytes(message.getTransientPublicKeyBytes().getValue());
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeHostKeyBytes();
        serializeTransientPublicKey();
    }
}
