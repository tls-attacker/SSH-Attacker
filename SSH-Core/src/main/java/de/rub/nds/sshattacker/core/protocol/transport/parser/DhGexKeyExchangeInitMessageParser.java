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
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeInitMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeInitMessageParser
        extends SshMessageParser<DhGexKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /*
        public DhGexKeyExchangeInitMessageParser(byte[] array) {
            super(array);
        }
        public DhGexKeyExchangeInitMessageParser(byte[] array, int startPosition) {
            super(array, startPosition);
        }
    */

    public DhGexKeyExchangeInitMessageParser(InputStream stream) {
        super(stream);
    }

    /*    @Override
    protected DhGexKeyExchangeInitMessage createMessage() {
        return new DhGexKeyExchangeInitMessage();
    }*/

    public void parseEphemeralPublicKey(DhGexKeyExchangeInitMessage message) {
        message.setEphemeralPublicKeyLength(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug(
                "Ephemeral public key (client) length: " + message.getEphemeralPublicKeyLength());
        message.setEphemeralPublicKey(
                parseBigIntField(message.getEphemeralPublicKeyLength().getValue()));
        LOGGER.debug(
                "Ephemeral public key (client): " + message.getEphemeralPublicKey().getValue());
    }

    @Override
    protected void parseMessageSpecificContents(DhGexKeyExchangeInitMessage message) {
        parseEphemeralPublicKey(message);
    }

    @Override
    public void parse(DhGexKeyExchangeInitMessage message) {
        parseMessageSpecificContents(message);
    }
}
