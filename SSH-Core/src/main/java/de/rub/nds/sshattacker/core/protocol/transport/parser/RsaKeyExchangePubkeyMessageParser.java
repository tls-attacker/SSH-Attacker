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

    public RsaKeyExchangePubkeyMessageParser(byte[] array) {
        super(array);
    }

    public RsaKeyExchangePubkeyMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected RsaKeyExchangePubkeyMessage createMessage() {
        return new RsaKeyExchangePubkeyMessage();
    }

    private void parseHostKeyBytes() {
        int hostKeyBytesLength = parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        message.setHostKeyBytesLength(hostKeyBytesLength);
        LOGGER.debug("Host key bytes length: {}", hostKeyBytesLength);
        byte[] hostKeyBytes = parseByteArrayField(hostKeyBytesLength);
        message.setHostKeyBytes(hostKeyBytes);
        LOGGER.debug("Host key bytes: {}", hostKeyBytes);
    }

    private void parseTransientPublicKey() {
        int transientPublicKeyBytesLength =
                parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        message.setTransientPublicKeyBytesLength(transientPublicKeyBytesLength);
        LOGGER.debug("Transient public key length: {}", transientPublicKeyBytesLength);
        byte[] transientPublicKeyBytes = parseByteArrayField(transientPublicKeyBytesLength);
        message.setTransientPublicKeyBytes(transientPublicKeyBytes);
        LOGGER.debug("Transient public key: {}", transientPublicKeyBytes);
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseHostKeyBytes();
        parseTransientPublicKey();
    }
}
