/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser.extension;

import de.rub.nds.sshattacker.core.protocol.transport.message.extension.NoFlowControlExtension;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class NoFlowControlExtensionParser extends AbstractExtensionParser<NoFlowControlExtension> {

    private static final Logger LOGGER = LogManager.getLogger();

    public NoFlowControlExtensionParser(byte[] array) {
        super(array);
    }

    public NoFlowControlExtensionParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected NoFlowControlExtension createExtension() {
        return new NoFlowControlExtension();
    }

    private void parseChoice() {
        int choiceLength = parseIntField();
        extension.setChoiceLength(choiceLength);
        LOGGER.debug("Choice length: {}", choiceLength);
        String choice = parseByteString(choiceLength, StandardCharsets.US_ASCII);
        extension.setChoice(choice);
        LOGGER.debug("Choice: {}", choice);
    }

    @Override
    protected void parseExtensionValue() {
        parseChoice();
    }
}
