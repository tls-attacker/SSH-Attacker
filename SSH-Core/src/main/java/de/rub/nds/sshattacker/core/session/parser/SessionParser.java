/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.session.parser;

/*
import de.rub.nds.sshattacker.core.constants.ProtocolMessageType;
import de.rub.nds.sshattacker.core.constants.ProtocolVersion;
 */

import de.rub.nds.sshattacker.core.constants.SessionByteLength;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.layer.data.Parser;
import de.rub.nds.sshattacker.core.session.Session;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SessionParser extends Parser<Session> {

    private static final Logger LOGGER = LogManager.getLogger();

    // private final ProtocolVersion version;
    private final SshContext sshContext;

    /*public SessionParser(InputStream stream, ProtocolVersion version, SshContext sshContext) {
        super(stream);
        //this.version = version;
        this.sshContext = sshContext;
    }*/

    public SessionParser(SshContext sshContext, InputStream stream) {
        super(stream);
        // this.version = version;
        this.sshContext = sshContext;
    }

    @Override
    public void parse(Session session) {
        LOGGER.debug("Parsing Record");
        /*parseContentType(session);
        ProtocolMessageType protocolMessageType =
                ProtocolMessageType.getContentType(session.getContentType().getValue());
        if (protocolMessageType == null) {
            protocolMessageType = ProtocolMessageType.UNKNOWN;
        }
        session.setContentMessageType(protocolMessageType);
        parseVersion(session);
        if (version.isDTLS()) {
            parseEpoch(session);
            parseSequenceNumber(session);
            if (protocolMessageType == ProtocolMessageType.TLS12_CID) {
                parseConnectionId(session);
            }
        }
        parseLength(session);
        parseProtocolMessageBytes(session);
        session.setCompleteRecordBytes(getAlreadyParsed());*/
    }

    private void parseEpoch(Session session) {
        session.setEpoch(parseIntField(SessionByteLength.DTLS_EPOCH));
        LOGGER.debug("Epoch: " + session.getEpoch().getValue());
    }

    private void parseSequenceNumber(Session session) {
        session.setSequenceNumber(parseBigIntField(SessionByteLength.DTLS_SEQUENCE_NUMBER));
        LOGGER.debug("SequenceNumber: " + session.getSequenceNumber().getValue());
    }

    private void parseConnectionId(Session session) {
        /*int connectionIdLength =
                sshContext
                        .getRecordLayer()
                        .getDecryptor()
                        .getRecordCipher(session.getEpoch().getValue())
                        .getState()
                        .getConnectionId()
                        .length;
        session.setConnectionId(parseByteArrayField(connectionIdLength));*/
        LOGGER.debug("ConnectionID: {}", session.getConnectionId().getValue());
    }

    private void parseContentType(Session session) {
        session.setContentType(parseByteField(SessionByteLength.CONTENT_TYPE));
        LOGGER.debug("ContentType: " + session.getContentType().getValue());
    }

    private void parseVersion(Session session) {
        session.setProtocolVersion(parseByteArrayField(SessionByteLength.PROTOCOL_VERSION));
        LOGGER.debug("ProtocolVersion: {}", session.getProtocolVersion().getValue());
    }

    private void parseLength(Session session) {
        session.setLength(parseIntField(SessionByteLength.RECORD_LENGTH));
        LOGGER.debug("Length: " + session.getLength().getValue());
    }

    private void parseProtocolMessageBytes(Session session) {
        session.setProtocolMessageBytes(parseByteArrayField(session.getLength().getValue()));
        LOGGER.debug("ProtocolMessageBytes: {}", session.getProtocolMessageBytes().getValue());
    }
}
