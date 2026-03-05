/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestCancelStreamlocalForwardOpenSshMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.GlobalRequestCancelStreamlocalForwardOpenSshMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.GlobalRequestCancelStreamlocalForwardOpenSshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.GlobalRequestCancelStreamlocalForwardOpenSshMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class GlobalRequestCancelStreamlocalForwardOpenSshMessageHandler
        extends SshMessageHandler<GlobalRequestCancelStreamlocalForwardOpenSshMessage> {

    @Override
    public void adjustContext(
            SshContext context, GlobalRequestCancelStreamlocalForwardOpenSshMessage object) {}

    @Override
    public GlobalRequestCancelStreamlocalForwardOpenSshMessageParser getParser(
            byte[] array, SshContext context) {
        return new GlobalRequestCancelStreamlocalForwardOpenSshMessageParser(array);
    }

    @Override
    public GlobalRequestCancelStreamlocalForwardOpenSshMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new GlobalRequestCancelStreamlocalForwardOpenSshMessageParser(array, startPosition);
    }

    public static final GlobalRequestCancelStreamlocalForwardOpenSshMessagePreparator PREPARATOR =
            new GlobalRequestCancelStreamlocalForwardOpenSshMessagePreparator();

    public static final GlobalRequestCancelStreamlocalForwardOpenSshMessageSerializer SERIALIZER =
            new GlobalRequestCancelStreamlocalForwardOpenSshMessageSerializer();
}
