/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.protocol.connection.message.TcpIpForwardCancelMessage;

public class TcpIpForwardCancelMessageParser extends GlobalRequestMessageParser<TcpIpForwardCancelMessage>{
    
    public TcpIpForwardCancelMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public TcpIpForwardCancelMessage createMessage() {
        return new TcpIpForwardCancelMessage();
    }
}
