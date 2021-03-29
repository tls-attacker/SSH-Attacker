/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.config.delegate;

import de.rub.nds.sshattacker.config.Config;
import de.rub.nds.sshattacker.exceptions.ConfigurationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class Delegate {

    protected static final Logger LOGGER = LogManager.getLogger();

    public abstract void applyDelegate(Config config) throws ConfigurationException;
}
