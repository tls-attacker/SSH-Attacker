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
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeRequestMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeRequestMessageParser
        extends SshMessageParser<DhGexKeyExchangeRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /* public DhGexKeyExchangeRequestMessageParser(byte[] array) {
        super(array);
    }
    public DhGexKeyExchangeRequestMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }*/
    public DhGexKeyExchangeRequestMessageParser(InputStream stream) {
        super(stream);
    }

    /*
        @Override
        public DhGexKeyExchangeRequestMessage createMessage() {
            return new DhGexKeyExchangeRequestMessage();
        }
    */

    public void parseMinimalGroupSize(DhGexKeyExchangeRequestMessage message) {
        message.setMinimalGroupSize((parseIntField(DataFormatConstants.UINT32_SIZE)));
        LOGGER.debug("Minimal DH group size: {} bits", message.getMinimalGroupSize().getValue());
    }

    public void parsePreferredGroupSize(DhGexKeyExchangeRequestMessage message) {
        message.setPreferredGroupSize(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug(
                "Preferred DH group size: {} bits", message.getPreferredGroupSize().getValue());
    }

    public void parseMaximalGroupSize(DhGexKeyExchangeRequestMessage message) {
        message.setMaximalGroupSize(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Maximal DH group size: {} bits", message.getMaximalGroupSize().getValue());
    }

    @Override
    protected void parseMessageSpecificContents(DhGexKeyExchangeRequestMessage message) {
        parseMinimalGroupSize(message);
        parsePreferredGroupSize(message);
        parseMaximalGroupSize(message);
    }

    @Override
    public void parse(DhGexKeyExchangeRequestMessage message) {
        parseProtocolMessageContents(message);
    }
}
