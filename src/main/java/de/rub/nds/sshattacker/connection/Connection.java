package de.rub.nds.sshattacker.connection;

import de.rub.nds.sshattacker.transport.ConnectionEndType;
import de.rub.nds.sshattacker.transport.TransportHandlerType;
import java.io.Serializable;
import java.util.Objects;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlTransient;

@XmlTransient
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class Connection implements Serializable {

    protected Integer port = null;
    protected String hostname = null;
    protected TransportHandlerType transportHandlerType = null;
    protected Integer timeout = null;

    public Connection() {
    }

    public Connection(Integer port) {
        this.port = port;
    }

    public Connection(Integer port, String hostname) {
        this.port = port;
        this.hostname = hostname;
    }

    public Connection(Connection other) {
        port = other.port;
        hostname = other.hostname;
        transportHandlerType = other.transportHandlerType;
        timeout = other.timeout;
    }

    public Integer getPort() {
        return port;
    }

    public void setPort(Integer port) {
        this.port = port;
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public void setTransportHandlerType(TransportHandlerType transportHandlerType) {
        this.transportHandlerType = transportHandlerType;
    }

    public TransportHandlerType getTransportHandlerType() {
        return transportHandlerType;
    }

    public void setTimeout(Integer timeout) {
        this.timeout = timeout;
    }

    public Integer getTimeout() {
        return timeout;
    }

    /**
     * Get the connection end type of the connection end. This must be
     * implemented by all children.
     *
     * @return the connection end type of the connection end.
     */
    public abstract ConnectionEndType getLocalConnectionEndType();

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 41 * hash + Objects.hashCode(this.port);
        hash = 41 * hash + Objects.hashCode(this.transportHandlerType);
        hash = 41 * hash + Objects.hashCode(this.timeout);
        hash = 41 * hash + Objects.hashCode(this.getLocalConnectionEndType());
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final Connection other = (Connection) obj;
        if (!Objects.equals(this.port, other.port)) {
            return false;
        }
        if (this.transportHandlerType != other.transportHandlerType) {
            return false;
        }
        if (!Objects.equals(this.timeout, other.timeout)) {
            return false;
        }
        return Objects.equals(this.getLocalConnectionEndType(), other.getLocalConnectionEndType());
    }
}
