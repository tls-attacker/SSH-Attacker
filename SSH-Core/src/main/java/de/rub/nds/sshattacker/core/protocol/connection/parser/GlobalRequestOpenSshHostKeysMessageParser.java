/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestOpenSshHostKeysMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class GlobalRequestOpenSshHostKeysMessageParser
        extends GlobalRequestMessageParser<GlobalRequestOpenSshHostKeysMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public GlobalRequestOpenSshHostKeysMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(GlobalRequestOpenSshHostKeysMessage message) {
        parseProtocolMessageContents(message);
    }

    private void parseHostKeys(GlobalRequestOpenSshHostKeysMessage message) {
        message.setHostKeys(this.parseByteArrayField(this.getBytesLeft()));
        LOGGER.debug(
                "Host keys blob: {}",
                ArrayConverter.bytesToRawHexString(message.getHostKeys().getValue()));
    }

    @Override
    protected void parseMessageSpecificContents(GlobalRequestOpenSshHostKeysMessage message) {
        super.parseMessageSpecificContents(message);
        parseHostKeys(message);
    }
}
