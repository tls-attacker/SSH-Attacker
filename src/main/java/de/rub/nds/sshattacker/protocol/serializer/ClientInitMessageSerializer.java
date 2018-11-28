package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.protocol.core.message.Serializer;
import de.rub.nds.sshattacker.constants.ByteConstants;
import de.rub.nds.sshattacker.constants.CharConstants;
import de.rub.nds.sshattacker.protocol.message.ClientInitMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ClientInitMessageSerializer extends Serializer<ClientInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ClientInitMessage msg;

    public ClientInitMessageSerializer(ClientInitMessage msg) {
        this.msg = msg;
    }

    ;

    private void serializeVersion() {
        if (msg.getVersion().getValue() == null) {
            LOGGER.debug("Version: null");
        } else {
            LOGGER.debug("Version: " + msg.getVersion().getValue());
            appendString(msg.getVersion().getValue());
        }
    }

    private void serializeComment() {
        if (msg.getComment().getValue() == null) {
            LOGGER.debug("Comment: null");
        } else {
            LOGGER.debug("Comment: " + msg.getComment().getValue());
            appendString(String.valueOf(CharConstants.VERSION_COMMENT_SEPARATOR));
            appendString(msg.getComment().getValue());
        }
    }

    private void serializeCRNL() {
        appendBytes(new byte[]{ByteConstants.CR, ByteConstants.NL});
    }

    @Override
    protected byte[] serializeBytes() {
        serializeVersion();
        serializeComment();
        serializeCRNL();
        return getAlreadySerialized();
    }
}
