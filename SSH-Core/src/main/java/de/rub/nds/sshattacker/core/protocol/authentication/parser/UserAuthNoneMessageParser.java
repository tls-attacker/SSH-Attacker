/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.parser;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthNoneMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthNoneMessageParser extends UserAuthRequestMessageParser<UserAuthNoneMessage> {

    private static final Logger LOGGER = LogManager.getLogger();


    public UserAuthNoneMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(UserAuthNoneMessage message) {
        LOGGER.debug("Parsing UserAuthBannerMessage");
        parseProtocolMessageContents(message);
        message.setCompleteResultingMessage(getAlreadyParsed());
    }

    @Override
    protected void parseMessageSpecificContents(UserAuthNoneMessage message) {
        super.parseMessageSpecificContents(message);
    }
}
