/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import de.rub.nds.sshattacker.core.state.SshContext;

public interface Handler<T> {

    Parser<T> getParser(byte[] array, SshContext context);

    Parser<T> getParser(byte[] array, int startPosition, SshContext context);

    void adjustContext(SshContext context, T object);
}
