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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RsaKeyExchangePubkeyMessageParser
        extends SshMessageParser<RsaKeyExchangePubkeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RsaKeyExchangePubkeyMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected RsaKeyExchangePubkeyMessage createMessage() {
        return new RsaKeyExchangePubkeyMessage();
    }

    private void parseHostKey() {
        message.setHostKeyLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Host key length: " + message.getHostKeyLength().getValue());
        message.setHostKey(parseByteArrayField(message.getHostKeyLength().getValue()));
        LOGGER.debug("Host key: " + message.getHostKey());
    }

    private void parseTransientPublicKey() {
        message.setTransientPubkeyLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug(
                "Transient public key length: " + message.getTransientPubkeyLength().getValue());
        message.setTransientPubkey(
                parseByteArrayField(message.getTransientPubkeyLength().getValue()));
        LOGGER.debug("Transient public key: " + message.getTransientPubkey());
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseHostKey();
        parseTransientPublicKey();
    }
}
