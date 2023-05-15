/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangeSecretMessage;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RsaKeyExchangeSecretMessageParser
        extends SshMessageParser<RsaKeyExchangeSecretMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RsaKeyExchangeSecretMessageParser(byte[] array) {
        super(array);
    }

    public RsaKeyExchangeSecretMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public RsaKeyExchangeSecretMessage createMessage() {
        return new RsaKeyExchangeSecretMessage();
    }

    private void parseEncryptedSecret() {
        message.setEncryptedSecretLength(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Encrypted secret length: {}", message.getEncryptedSecretLength().getValue());
        message.setEncryptedSecret(
                parseByteArrayField(message.getEncryptedSecretLength().getValue()));
        LOGGER.debug("Encrypted secret: {}", message.getEncryptedSecret());
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseEncryptedSecret();
    }
}
