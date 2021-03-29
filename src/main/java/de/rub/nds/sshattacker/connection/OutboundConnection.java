/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.connection;

import de.rub.nds.tlsattacker.transport.ConnectionEndType;

public class OutboundConnection extends AliasedConnection {

    private static final ConnectionEndType LOCAL_CONNECTION_END_TYPE = ConnectionEndType.CLIENT;

    public OutboundConnection() {
    }

    public OutboundConnection(Integer port) {
        super(port);
    }

    public OutboundConnection(Integer port, String hostname) {
        super(port, hostname);
    }

    public OutboundConnection(String alias) {
        super(alias);
    }

    public OutboundConnection(String alias, Integer port) {
        super(alias, port);
    }

    public OutboundConnection(String alias, Integer port, String hostname) {
        super(alias, port, hostname);
    }

    public OutboundConnection(OutboundConnection other) {
        this.alias = other.alias;
        this.hostname = other.hostname;
        this.port = other.port;
        this.timeout = other.timeout;
        this.transportHandlerType = other.transportHandlerType;
    }

    @Override
    public ConnectionEndType getLocalConnectionEndType() {
        return LOCAL_CONNECTION_END_TYPE;
    }

    @Override
    public String toString() {
        return "OutboundConnection{" + " alias=" + alias + " host=" + hostname + " port=" + port + " type="
                + transportHandlerType + " timeout=" + timeout + "}";
    }

    @Override
    public String toCompactString() {
        return "OutboundConnection[" + alias + ":" + hostname + ":" + port + "]";
    }

    @Override
    public void normalize(AliasedConnection defaultCon) {
        if (defaultCon == null) {
            defaultCon = new OutboundConnection();
        }
        super.normalize(defaultCon);
    }

    @Override
    public void filter(AliasedConnection defaultCon) {
        if (defaultCon == null) {
            defaultCon = new OutboundConnection();
        }
        super.filter(defaultCon);
    }

    @Override
    public OutboundConnection getCopy() {
        return new OutboundConnection(this);
    }
}
