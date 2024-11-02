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
import de.rub.nds.sshattacker.core.protocol.transport.message.DhKeyExchangeInitMessage;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhKeyExchangeInitMessageParser extends SshMessageParser<DhKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhKeyExchangeInitMessageParser(byte[] array) {
        super(array);
    }

    public DhKeyExchangeInitMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected DhKeyExchangeInitMessage createMessage() {
        return new DhKeyExchangeInitMessage();
    }

    private void parseEphemeralPublicKey() {
        int ephemeralPublicKeyLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        message.setEphemeralPublicKeyLength(ephemeralPublicKeyLength);
        LOGGER.debug("Ephemeral public key (client) length: {}", ephemeralPublicKeyLength);
        BigInteger ephemeralPublicKey = parseBigIntField(ephemeralPublicKeyLength);
        message.setEphemeralPublicKey(ephemeralPublicKey);
        LOGGER.debug("Ephemeral public key (client): {}", ephemeralPublicKey);
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseEphemeralPublicKey();
    }
}
