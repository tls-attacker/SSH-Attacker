package de.rub.nds.sshattacker.connection;

import de.rub.nds.tlsattacker.transport.ConnectionEndType;

public class InboundConnection extends AliasedConnection {

    private static final ConnectionEndType LOCAL_CONNECTION_END_TYPE = ConnectionEndType.SERVER;

    public InboundConnection() {
    }

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
        StringBuilder sb = new StringBuilder("InboundConnection{");
        sb.append(" alias=").append(alias);
        sb.append(" port=").append(port);
        sb.append(" type=").append(transportHandlerType);
        sb.append(" timeout=").append(timeout);
        sb.append("}");
        return sb.toString();
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder("InboundConnection[");
        sb.append(alias);
        sb.append(":").append(port).append("]");
        return sb.toString();
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
