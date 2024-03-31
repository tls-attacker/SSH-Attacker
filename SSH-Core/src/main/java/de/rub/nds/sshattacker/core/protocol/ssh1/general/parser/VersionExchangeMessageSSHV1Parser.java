/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.general.parser;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.CharConstants;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessageParser;
import de.rub.nds.sshattacker.core.protocol.ssh1.general.message.VersionExchangeMessageSSHV1;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class VersionExchangeMessageSSHV1Parser
        extends ProtocolMessageParser<VersionExchangeMessageSSHV1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public VersionExchangeMessageSSHV1Parser(InputStream stream) {
        super(stream);
    }

    private void parseVersion(VersionExchangeMessageSSHV1 message) {
        // parse till CR NL (and remove them)
        String result = parseStringTill(CharConstants.NEWLINE);
        if (result.contains("\r")) {
            message.setEndOfMessageSequence("\r\n");
        } else {
            message.setEndOfMessageSequence("\n");
        }
        result = result.replace("\n", "").replace("\r", "");

        String[] parts = result.split(String.valueOf(CharConstants.VERSION_COMMENT_SEPARATOR), 2);
        message.setVersion(parts[0]);
        LOGGER.debug("Version: {}", backslashEscapeString(parts[0]));
        if (parts.length == 2) {
            message.setComment(parts[1]);
            LOGGER.debug("Comment: {}", backslashEscapeString(parts[1]));
        } else {
            message.setComment("");
            LOGGER.debug("Comment: [none]");
        }
    }

    // @Override
    public void parseProtocolMessageContents(VersionExchangeMessageSSHV1 message) {
        parseVersion(message);
    }

    @Override
    public void parse(VersionExchangeMessageSSHV1 message) {
        parseProtocolMessageContents(message);
    }
}
