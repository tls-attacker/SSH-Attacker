/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.protocol.core.message.Parser;
import de.rub.nds.sshattacker.protocol.message.ClientInitMessage;
import de.rub.nds.sshattacker.constants.ByteConstants;
import de.rub.nds.sshattacker.constants.InitMessageConstants;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ClientInitMessageParser extends Parser<ClientInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ClientInitMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    private void parseVersion(ClientInitMessage msg) {
        // parse till CR NL
        String result = this.parseStringTill(new byte[]{ByteConstants.CR, ByteConstants.NL});
        if (result.contains(String.valueOf(InitMessageConstants.VERSION_COMMENT_SEPARATOR))) {
            // contains a comment
            String[] parts = result.split(String.valueOf(InitMessageConstants.VERSION_COMMENT_SEPARATOR), 2);
            msg.setVersion(parts[0]);
            LOGGER.debug("Version: " + parts[0]);
            if (parts.length >= 2) {
                msg.setComment(parts[1]);
                LOGGER.debug("Comment: " + parts[1]);
            }
        } else {
            msg.setVersion(result);
            LOGGER.debug("Version: " + result);
            msg.setComment((String) null);
            LOGGER.debug("Comment: null");
        }
    }

    @Override
    public ClientInitMessage parse() {
        ClientInitMessage msg = new ClientInitMessage();
        this.parseVersion(msg);
        return msg;
    }
}
