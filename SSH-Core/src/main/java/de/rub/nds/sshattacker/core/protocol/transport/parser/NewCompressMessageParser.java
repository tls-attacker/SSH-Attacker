/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.NewCompressMessage;
import java.io.InputStream;

public class NewCompressMessageParser extends SshMessageParser<NewCompressMessage> {

    public NewCompressMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(NewCompressMessage message) {
        parseProtocolMessageContents(message);
    }

    /*    public NewCompressMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected NewCompressMessage createMessage() {
        return new NewCompressMessage();
    }*/

    @Override
    protected void parseMessageSpecificContents(NewCompressMessage message) {}
}
