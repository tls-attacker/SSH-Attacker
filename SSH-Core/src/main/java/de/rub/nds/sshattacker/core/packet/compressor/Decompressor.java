/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.compressor;

import de.rub.nds.sshattacker.core.exceptions.DecompressionException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class Decompressor<T> {

    protected static final Logger LOGGER = LogManager.getLogger();

    public abstract void decompress(T object) throws DecompressionException;
}
