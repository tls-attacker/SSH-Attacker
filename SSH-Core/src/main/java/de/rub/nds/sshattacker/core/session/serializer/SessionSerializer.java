/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.session.serializer;

import de.rub.nds.sshattacker.core.constants.SessionByteLength;
import de.rub.nds.sshattacker.core.layer.data.Serializer;
import de.rub.nds.sshattacker.core.session.Session;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SessionSerializer extends Serializer<Session> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Session session;

    public SessionSerializer(Session session) {
        this.session = session;
    }

    @Override
    protected byte[] serializeBytes() {
        LOGGER.debug("Serializing Record");
        writeContentType(session);
        writeProtocolVersion(session);
        if (session.getEpoch() != null) {
            writeEpoch(session);
            writeSequenceNumber(session);
        }
        if (session.getConnectionId() != null) {
            writeConnectionId(session);
        }
        writeLength(session);
        writeProtocolMessageBytes(session);
        return getAlreadySerialized();
    }

    private void writeContentType(Session session) {
        appendByte(session.getContentType().getValue());
        LOGGER.debug("ContentType: " + session.getContentType().getValue());
    }

    private void writeProtocolVersion(Session session) {
        appendBytes(session.getProtocolVersion().getValue());
        LOGGER.debug("ProtocolVersion: {}", session.getProtocolVersion().getValue());
    }

    private void writeLength(Session session) {
        appendInt(session.getLength().getValue(), SessionByteLength.RECORD_LENGTH);
        LOGGER.debug("Length: " + session.getLength().getValue());
    }

    private void writeConnectionId(Session session) {
        appendBytes(session.getConnectionId().getValue());
        LOGGER.debug("ConnectionID: {}", session.getConnectionId().getValue());
    }

    private void writeEpoch(Session session) {
        appendInt(session.getEpoch().getValue(), SessionByteLength.DTLS_EPOCH);
        LOGGER.debug("Epoch: " + session.getEpoch().getValue());
    }

    private void writeSequenceNumber(Session session) {
        appendBigInteger(
                session.getSequenceNumber().getValue(), SessionByteLength.DTLS_SEQUENCE_NUMBER);
        LOGGER.debug("SequenceNumber: " + session.getSequenceNumber().getValue());
    }

    private void writeProtocolMessageBytes(Session session) {
        appendBytes(session.getProtocolMessageBytes().getValue());
        LOGGER.debug("ProtocolMessageBytes: {}", session.getProtocolMessageBytes().getValue());
    }
}
