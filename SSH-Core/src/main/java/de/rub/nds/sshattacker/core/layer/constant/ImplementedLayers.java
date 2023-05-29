/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.layer.constant;

/** Holds all implemented layers of the TLS-Core, not limited to any layer of the ISO stack */
public enum ImplementedLayers implements LayerType {
    TCP,
    AuthenticationLayer,
    ConnectionLayer,
    TransportLayer,
    Session,
    SSHv1,
    SSHv2;

    @Override
    public String getName() {
        return this.name();
    }
}
