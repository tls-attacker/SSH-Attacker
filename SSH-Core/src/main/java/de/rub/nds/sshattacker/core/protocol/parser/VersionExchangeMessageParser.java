/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.sshattacker.core.protocol.parser;

import de.rub.nds.sshattacker.core.constants.ByteConstants;
import de.rub.nds.sshattacker.core.constants.CharConstants;
import de.rub.nds.sshattacker.core.protocol.message.VersionExchangeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class VersionExchangeMessageParser extends Parser<VersionExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public VersionExchangeMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    private void parseVersion(VersionExchangeMessage msg) {
        // parse till CR NL (and remove them)
        String result = this.parseStringTill(new byte[] { ByteConstants.CARRIAGE_RETURN, ByteConstants.NEWLINE })
                .replace("\r\n", "");
        if (result.contains(String.valueOf(CharConstants.VERSION_COMMENT_SEPARATOR))) {
            // contains a comment
            String[] parts = result.split(String.valueOf(CharConstants.VERSION_COMMENT_SEPARATOR), 2);
            msg.setVersion(parts[0]);
            LOGGER.debug("Version: " + parts[0]);
            if (parts.length >= 2) {
                msg.setComment(parts[1]);
                LOGGER.debug("Comment: " + parts[1]);
            }
        } else {
            msg.setVersion(result);
            LOGGER.debug("Version: " + result);
            msg.setComment("");
            LOGGER.debug("Comment: null");
        }
    }

    @Override
    public VersionExchangeMessage parse() {
        VersionExchangeMessage msg = new VersionExchangeMessage();
        this.parseVersion(msg);
        return msg;
    }
}
