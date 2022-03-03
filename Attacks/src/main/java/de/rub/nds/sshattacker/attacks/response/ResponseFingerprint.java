/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.response;

import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.DisconnectMessage;
import de.rub.nds.tlsattacker.transport.socket.SocketState;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElementRef;
import javax.xml.bind.annotation.XmlElementWrapper;
import java.util.List;
import java.util.Objects;

/** */
@XmlAccessorType(XmlAccessType.FIELD)
public class ResponseFingerprint {
    @XmlElementWrapper @XmlElementRef private List<ProtocolMessage<?>> messageList;

    private SocketState socketState;

    public ResponseFingerprint() {}

    /**
     * @param messageList List of protocol messages
     * @param socketState Socket state
     */
    public ResponseFingerprint(List<ProtocolMessage<?>> messageList, SocketState socketState) {
        this.messageList = messageList;
        this.socketState = socketState;
    }

    public SocketState getSocketState() {
        return socketState;
    }

    public List<ProtocolMessage<?>> getMessageList() {
        return messageList;
    }

    @Override
    public String toString() {

        StringBuilder messages = new StringBuilder();
        for (ProtocolMessage<?> someMessage : this.messageList) {
            messages.append(someMessage.toCompactString()).append(",");
        }

        return "ResponseFingerprint[ Messages=[" + messages + "], SocketState=" + socketState + ']';
    }

    public String toCompactString() {
        StringBuilder messages = new StringBuilder();
        for (ProtocolMessage<?> someMessage : this.messageList) {
            messages.append(someMessage.toCompactString()).append(",");
        }
        return messages.append("|").append(socketState).toString();
    }

    public String toHumanReadable() {
        StringBuilder resultString = new StringBuilder();
        for (ProtocolMessage<?> msg : messageList) {
            if (!(msg instanceof SshMessage)) {
                resultString.append("{").append(msg.getClass().getName()).append("} ");
                continue;
            }

            SshMessage<?> message = (SshMessage<?>) msg;
            resultString.append(message.getClass().getName()).append("}");
            resultString.append(" ");
        }
        resultString.append(" ");
        if (socketState != null) {
            switch (socketState) {
                case CLOSED:
                    resultString.append("X");
                    break;
                case DATA_AVAILABLE:
                    resultString.append("$$$");
                    break;
                case IO_EXCEPTION:
                    resultString.append("§");
                    break;
                case SOCKET_EXCEPTION:
                    resultString.append("@");
                    break;
                case TIMEOUT:
                    resultString.append("T");
                    break;
                case UP:
                    resultString.append("U");
                    break;
                default: // should never occur as all ENUM types are handled
                    throw new UnsupportedOperationException("Unknown Socket State");
            }
        }
        return resultString.toString();
    }

    /**
     * Overrides the built-in hashCode() function. toString().hashCode() assures same hashes for
     * responses with essentially the same content but differences in their record bytes.
     *
     * @return The hash of the string representation
     */
    @Override
    public int hashCode() {
        return toString().hashCode();
    }

    /**
     * Returns whether two ResponseFingerprints are equal using the {@link FingerPrintChecker}.
     *
     * @param obj ResponseFingerprint to compare this one to
     * @return True, if both ResponseFingerprints are equal
     */
    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof ResponseFingerprint)) {
            return false;
        }
        EqualityError equalityError =
                FingerPrintChecker.checkEquality(this, (ResponseFingerprint) obj);
        return equalityError == EqualityError.NONE;
    }

    /**
     * @param fingerprint The fingerprint to be compared to
     * @return If this fingerprint and the other fingerprint are compatible
     */
    public boolean areCompatible(ResponseFingerprint fingerprint) {
        if (socketState != SocketState.TIMEOUT
                && fingerprint.getSocketState() != SocketState.TIMEOUT) {
            if (fingerprint.getSocketState() != socketState) {
                return false;
            }
        }
        int minNumberOfMessages = fingerprint.getMessageList().size();
        if (this.messageList.size() < minNumberOfMessages) {
            minNumberOfMessages = this.messageList.size();
        }
        for (int i = 0; i < minNumberOfMessages; i++) {
            ProtocolMessage<?> messageOne = this.getMessageList().get(i);
            ProtocolMessage<?> messageTwo = fingerprint.getMessageList().get(i);
            if (!checkMessagesAreRoughlyEqual(messageOne, messageTwo)) {
                return false;
            }
        }
        return true;
    }

    private boolean checkMessagesAreRoughlyEqual(
            ProtocolMessage<?> messageOne, ProtocolMessage<?> messageTwo) {
        if (!messageOne.getClass().equals(messageTwo.getClass())) {
            return false;
        }
        if (messageOne instanceof DisconnectMessage && messageTwo instanceof DisconnectMessage) {
            // Both are disconnects
            DisconnectMessage disconnectOne = (DisconnectMessage) messageOne;
            DisconnectMessage disconnectTwo = (DisconnectMessage) messageTwo;
            return Objects.equals(
                    disconnectOne.getDescription().getValue(),
                    disconnectTwo.getDescription().getValue());
        }
        // nothing more to check?
        return true;
    }
}
