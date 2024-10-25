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
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhKeyExchangeInitMessageParser extends SshMessageParser<DhKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhKeyExchangeInitMessageParser(InputStream stream) {
        super(stream);
    }

    public void parseEphemeralPublicKey(DhKeyExchangeInitMessage message) {
        message.setEphemeralPublicKeyLength(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug(
                "Ephemeral public key (client) length: {}", message.getEphemeralPublicKeyLength());
        message.setEphemeralPublicKey(
                parseBigIntField(message.getEphemeralPublicKeyLength().getValue()));
        LOGGER.debug(
                "Ephemeral public key (client): {}", message.getEphemeralPublicKey().getValue());
    }

    @Override
    protected void parseMessageSpecificContents(DhKeyExchangeInitMessage message) {
        parseEphemeralPublicKey(message);
    }

    @Override
    public void parse(DhKeyExchangeInitMessage message) {
        parseProtocolMessageContents(message);
    }
}
