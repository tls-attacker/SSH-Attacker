/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.UserMessageSSH1;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserMessageParser extends SshMessageParser<UserMessageSSH1> {
    private static final Logger LOGGER = LogManager.getLogger();

    public UserMessageParser(SshContext context, InputStream stream) {
        super(stream);
    }

    private void parseCRC(UserMessageSSH1 message) {
        byte[] CRC = parseByteArrayField(4);
        LOGGER.debug("CRC: {}", ArrayConverter.bytesToHexString(CRC));
    }

    private void parseUserName(UserMessageSSH1 message) {
        LOGGER.debug("parse INT-Filed");
        int lenght = parseIntField(4);
        LOGGER.debug("parse String of lenght {}", lenght);
        String username = parseByteString(lenght);
        message.setUsername(username);
        LOGGER.debug("Username is {}", username);
    }

    private void parseProtocolFlags(UserMessageSSH1 message) {}

    @Override
    protected void parseMessageSpecificContents(UserMessageSSH1 message) {
        parseUserName(message);
    }

    @Override
    public void parse(UserMessageSSH1 message) {
        parseProtocolMessageContents(message);
    }
}
