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
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeReplyMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeReplyMessageParser
        extends SshMessageParser<DhGexKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /*
        public DhGexKeyExchangeReplyMessageParser(byte[] array) {
            super(array);
        }
        public DhGexKeyExchangeReplyMessageParser(byte[] array, int startPosition) {
            super(array, startPosition);
        }
    */

    public DhGexKeyExchangeReplyMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(DhGexKeyExchangeReplyMessage message) {
        parseProtocolMessageContents(message);
    }

    /*    @Override
    public DhGexKeyExchangeReplyMessage createMessage() {
        return new DhGexKeyExchangeReplyMessage();
    }*/

    private void parseHostKeyBytes(DhGexKeyExchangeReplyMessage message) {
        message.setHostKeyBytesLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Host key bytes length: " + message.getHostKeyBytesLength().getValue());
        message.setHostKeyBytes(parseByteArrayField(message.getHostKeyBytesLength().getValue()));
        LOGGER.debug("Host key bytes: " + message.getHostKeyBytes());
    }

    private void parseEphemeralPublicKey(DhGexKeyExchangeReplyMessage message) {
        message.setEphemeralPublicKeyLength(
                parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug(
                "Ephemeral public key (server) length: "
                        + message.getEphemeralPublicKeyLength().getValue());
        message.setEphemeralPublicKey(
                parseBigIntField(message.getEphemeralPublicKeyLength().getValue()));
        LOGGER.debug(
                "Ephemeral public key (server): " + message.getEphemeralPublicKey().getValue());
    }

    private void parseSignature(DhGexKeyExchangeReplyMessage message) {
        message.setSignatureLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Signature length: " + message.getSignatureLength().getValue());
        message.setSignature(parseByteArrayField(message.getSignatureLength().getValue()));
        LOGGER.debug("Signature: " + message.getSignature());
    }

    @Override
    protected void parseMessageSpecificContents(DhGexKeyExchangeReplyMessage message) {
        parseHostKeyBytes(message);
        parseEphemeralPublicKey(message);
        parseSignature(message);
    }
}
