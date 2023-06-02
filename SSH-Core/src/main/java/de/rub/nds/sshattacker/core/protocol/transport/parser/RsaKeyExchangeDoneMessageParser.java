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
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangeDoneMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RsaKeyExchangeDoneMessageParser extends SshMessageParser<RsaKeyExchangeDoneMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /*
        public RsaKeyExchangeDoneMessageParser(byte[] array) {
            super(array);
        }
        public RsaKeyExchangeDoneMessageParser(byte[] array, int startPosition) {
            super(array, startPosition);
        }
    */

    public RsaKeyExchangeDoneMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(RsaKeyExchangeDoneMessage message) {
        parseMessageSpecificContents(message);
    }

    /*
        @Override
        protected RsaKeyExchangeDoneMessage createMessage() {
            return new RsaKeyExchangeDoneMessage();
        }
    */

    @Override
    protected void parseMessageSpecificContents(RsaKeyExchangeDoneMessage message) {
        parseSignature(message);
    }

    private void parseSignature(RsaKeyExchangeDoneMessage message) {
        message.setSignatureLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Signature length: " + message.getSignatureLength().getValue());
        message.setSignature(parseByteArrayField(message.getSignatureLength().getValue()));
        LOGGER.debug("Signature: " + message.getSignature());
    }
}
