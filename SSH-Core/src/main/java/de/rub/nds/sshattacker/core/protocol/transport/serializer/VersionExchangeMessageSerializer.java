/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.sshattacker.core.constants.CharConstants;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class VersionExchangeMessageSerializer extends Serializer<VersionExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final VersionExchangeMessage msg;

    public VersionExchangeMessageSerializer(VersionExchangeMessage msg) {
        this.msg = msg;
    }

    private void serializeVersion() {
        if (msg.getVersion().getValue().isEmpty()) {
            LOGGER.debug("Version: [none]");
        } else {
            LOGGER.debug("Version: " + msg.getVersion().getValue());
            appendString(msg.getVersion().getValue(), StandardCharsets.US_ASCII);
        }
    }

    private void serializeComment() {
        if (msg.getComment().getValue().isEmpty()) {
            LOGGER.debug("Comment: [none]");
        } else {
            LOGGER.debug("Comment: " + msg.getComment().getValue());
            appendString(
                    String.valueOf(CharConstants.VERSION_COMMENT_SEPARATOR),
                    StandardCharsets.US_ASCII);
            appendString(msg.getComment().getValue(), StandardCharsets.US_ASCII);
        }
    }

    private void serializeCRNL() {
        appendBytes(new byte[] {CharConstants.CARRIAGE_RETURN, CharConstants.NEWLINE});
    }

    @Override
    protected void serializeBytes() {
        serializeVersion();
        serializeComment();
        serializeCRNL();
    }
}
