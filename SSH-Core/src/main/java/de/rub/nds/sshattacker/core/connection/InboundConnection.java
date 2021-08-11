/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.connection;

import de.rub.nds.tlsattacker.transport.ConnectionEndType;

public class InboundConnection extends AliasedConnection {

    private static final ConnectionEndType LOCAL_CONNECTION_END_TYPE = ConnectionEndType.SERVER;

    public InboundConnection() {}

    public InboundConnection(Integer port) {
        super(port);
    }

    public InboundConnection(Integer port, String hostname) {
        super(port, hostname);
    }

    public InboundConnection(String alias) {
        super(alias);
    }

    public InboundConnection(String alias, Integer port) {
        super(alias, port);
    }

    public InboundConnection(String alias, Integer port, String hostname) {
        super(alias, port, hostname);
    }

    public InboundConnection(InboundConnection other) {
        this.alias = other.alias;
        this.hostname = other.hostname;
        this.ip = other.ip;
        this.port = other.port;
        this.proxyDataHostname = other.proxyDataHostname;
        this.proxyDataPort = other.proxyDataPort;
        this.proxyControlHostname = other.proxyControlHostname;
        this.proxyControlPort = other.proxyControlPort;
        this.timeout = other.timeout;
        this.transportHandlerType = other.transportHandlerType;
    }

    @Override
    public ConnectionEndType getLocalConnectionEndType() {
        return LOCAL_CONNECTION_END_TYPE;
    }

    @Override
    public String toString() {
        return "InboundConnection{"
                + " alias="
                + alias
                + " port="
                + port
                + " proxyDataHost="
                + proxyDataHostname
                + " proxyDataPort="
                + proxyDataPort
                + " proxyControlHost="
                + proxyControlHostname
                + " proxyControlPort="
                + proxyControlPort
                + " type="
                + transportHandlerType
                + " timeout="
                + timeout
                + "}";
    }

    @Override
    public String toCompactString() {
        return "InboundConnection[" + alias + ":" + port + "]";
    }

    @Override
    public void normalize(AliasedConnection defaultCon) {
        if (defaultCon == null) {
            defaultCon = new InboundConnection();
        }
        super.normalize(defaultCon);
    }

    @Override
    public void filter(AliasedConnection defaultCon) {
        if (defaultCon == null) {
            defaultCon = new InboundConnection();
        }
        super.filter(defaultCon);
    }

    @Override
    public InboundConnection getCopy() {
        return new InboundConnection(this);
    }
}
