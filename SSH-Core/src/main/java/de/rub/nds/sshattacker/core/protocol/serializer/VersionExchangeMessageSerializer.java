/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.serializer;

import de.rub.nds.sshattacker.core.constants.ByteConstants;
import de.rub.nds.sshattacker.core.constants.CharConstants;
import de.rub.nds.sshattacker.core.protocol.message.VersionExchangeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class VersionExchangeMessageSerializer extends Serializer<VersionExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final VersionExchangeMessage msg;

    public VersionExchangeMessageSerializer(VersionExchangeMessage msg) {
        this.msg = msg;
    }

    private void serializeVersion() {
        if (msg.getVersion().getValue().equals("")) {
            LOGGER.debug("Version: null");
        } else {
            LOGGER.debug("Version: " + msg.getVersion().getValue());
            appendString(msg.getVersion().getValue());
        }
    }

    private void serializeComment() {
        if (msg.getComment().getValue().equals("")) {
            LOGGER.debug("Comment: null");
        } else {
            LOGGER.debug("Comment: " + msg.getComment().getValue());
            appendString(String.valueOf(CharConstants.VERSION_COMMENT_SEPARATOR));
            appendString(msg.getComment().getValue());
        }
    }

    private void serializeCRNL() {
        appendBytes(new byte[] { ByteConstants.CARRIAGE_RETURN, ByteConstants.NEWLINE });
    }

    @Override
    protected byte[] serializeBytes() {
        serializeVersion();
        serializeComment();
        serializeCRNL();
        return getAlreadySerialized();
    }
}
