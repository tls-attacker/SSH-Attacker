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
import de.rub.nds.sshattacker.core.protocol.ssh1.message.DisconnectMessageSSH1;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.IgnoreMessageSSH1;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class IgnoreMessageSSHV1Parser extends SshMessageParser<IgnoreMessageSSH1> {
    private static final Logger LOGGER = LogManager.getLogger();

    public IgnoreMessageSSHV1Parser(SshContext context, InputStream stream) {
        super(stream);
    }

    private void parseCRC(DisconnectMessageSSH1 message) {
        byte[] CRC = parseByteArrayField(4);
        LOGGER.debug("CRC: {}", ArrayConverter.bytesToHexString(CRC));
    }

    private void parseIgnoreMessage(IgnoreMessageSSH1 message) {
        int lenght = parseIntField(4);
        String ignoreMsg = parseByteString(lenght);
        message.setIgnoreReason(ignoreMsg);
    }

    @Override
    protected void parseMessageSpecificContents(IgnoreMessageSSH1 message) {
        parseIgnoreMessage(message);
    }

    @Override
    public void parse(IgnoreMessageSSH1 message) {
        parseProtocolMessageContents(message);
    }
}
