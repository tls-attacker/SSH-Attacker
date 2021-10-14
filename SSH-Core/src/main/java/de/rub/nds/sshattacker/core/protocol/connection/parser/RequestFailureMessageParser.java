/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.message.RequestFailureMessage;

public class RequestFailureMessageParser extends SshMessageParser<RequestFailureMessage> {

    public RequestFailureMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public RequestFailureMessage createMessage() {
        return new RequestFailureMessage();
    }

    @Override
    protected void parseMessageSpecificContents() {}
}
