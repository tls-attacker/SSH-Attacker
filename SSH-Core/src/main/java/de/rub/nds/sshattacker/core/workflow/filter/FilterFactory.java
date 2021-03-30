/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.filter;

import de.rub.nds.sshattacker.core.config.Config;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class FilterFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    public static Filter createWorkflowTraceFilter(FilterType type, Config config) {
        if (type == FilterType.DEFAULT) {
            return new DefaultFilter(config);
        }
        throw new UnsupportedOperationException(type.name() + " not yet implemented");
    }

    private FilterFactory() {
    }
}
