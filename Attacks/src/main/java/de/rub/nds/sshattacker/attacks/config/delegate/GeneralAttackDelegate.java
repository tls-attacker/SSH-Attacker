/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.config.delegate;

import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.config.delegate.GeneralDelegate;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.config.Configurator;

/** A special GeneralDelegate which allows Attacks to add additional Parameters. */
public class GeneralAttackDelegate extends GeneralDelegate {

    /**
     * Adjusts the Config according to the specified values.
     *
     * @param config Config to adjust
     */
    @Override
    public void applyDelegate(Config config) {
        super.applyDelegate(config);
        if (isQuiet()) {
            Configurator.setAllLevels("de.rub.nds.tlsattacker.transport", Level.OFF);
            Configurator.setAllLevels("de.rub.nds.modifiablevariable", Level.OFF);
        }
    }
}
