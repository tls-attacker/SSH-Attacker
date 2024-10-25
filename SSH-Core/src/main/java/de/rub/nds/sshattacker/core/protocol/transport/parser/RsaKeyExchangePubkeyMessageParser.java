/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.sshattacker.core.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangePubkeyMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RsaKeyExchangePubkeyMessageParser
        extends SshMessageParser<RsaKeyExchangePubkeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RsaKeyExchangePubkeyMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(RsaKeyExchangePubkeyMessage message) {
        parseProtocolMessageContents(message);
    }

    private void parseHostKeyBytes(RsaKeyExchangePubkeyMessage message) {
        message.setHostKeyBytesLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Host key bytes length: {}", message.getHostKeyBytesLength().getValue());
        message.setHostKeyBytes(parseByteArrayField(message.getHostKeyBytesLength().getValue()));
        LOGGER.debug("Host key bytes: {}", message.getHostKeyBytes());
    }

    private void parseTransientPublicKey(RsaKeyExchangePubkeyMessage message) {
        message.setTransientPublicKeyBytesLength(
                parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug(
                "Transient public key length: {}",
                message.getTransientPublicKeyBytesLength().getValue());
        message.setTransientPublicKeyBytes(
                parseByteArrayField(message.getTransientPublicKeyBytesLength().getValue()));
        LOGGER.debug("Transient public key: {}", message.getTransientPublicKeyBytes());
    }

    @Override
    protected void parseMessageSpecificContents(RsaKeyExchangePubkeyMessage message) {
        parseHostKeyBytes(message);
        parseTransientPublicKey(message);
    }
}
