/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.layer;

import de.rub.nds.sshattacker.core.layer.data.DataContainer;

public abstract class DataContainerFilter {

    public abstract boolean filterApplies(DataContainer container);
}
