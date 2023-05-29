/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.session.preparator;

/*import de.rub.nds.sshattacker.core.record.compressor.RecordCompressor;
import de.rub.nds.sshattacker.core.record.crypto.Encryptor;
import de.rub.nds.sshattacker.core.constants.ProtocolVersion;
import de.rub.nds.sshattacker.core.constants.Tls13KeySetType;*/

import de.rub.nds.sshattacker.core.constants.ProtocolMessageType;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.layer.data.Preparator;
import de.rub.nds.sshattacker.core.session.Session;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** The cleanRecordBytes should be set when the record preparator received the record */
public class SessionPreparator extends Preparator<Session> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Session session;
    // private final Encryptor encryptor;
    private final SshContext sshContext;
    // private final RecordCompressor compressor;

    private ProtocolMessageType type;

    public SessionPreparator(
            SshContext sshContext,
            Session session,
            // Encryptor encryptor,
            ProtocolMessageType type) {
        // RecordCompressor compressor) {
        super(sshContext.getChooser(), session);
        this.session = session;
        // this.encryptor = encryptor;
        this.sshContext = sshContext;
        // this.compressor = compressor;
        this.type = type;
    }

    @Override
    public void prepare() {
        LOGGER.debug("Preparing Record");
        prepareConnectionId(session);
        session.prepareComputations();
        prepareContentType(session);
        prepareProtocolVersion(session);
        // compressor.compress(session);
        encrypt();
    }

    public void encrypt() {
        LOGGER.debug("Encrypting Record");
        /*if (chooser.getSelectedProtocolVersion().isTLS13()
                && session.getContentMessageType() == ProtocolMessageType.CHANGE_CIPHER_SPEC
                && !chooser.getConfig().isEncryptChangeCipherSpec()) {
            // The CCS message in TLS 1.3 is an exception that does not get
            // encrypted
            session.prepareComputations();
            session.setProtocolMessageBytes(session.getCleanProtocolMessageBytes().getValue());
        } else {
            encryptor.encrypt(session);
        }
        prepareLength(session);*/
    }

    private void prepareConnectionId(Session session) {
        /*if (chooser.getSelectedProtocolVersion().isDTLS()) {
            RecordLayer recordLayer = sshContext.getRecordLayer();
            byte[] connectionId =
                    recordLayer
                            .getEncryptor()
                            .getRecordCipher(recordLayer.getWriteEpoch())
                            .getState()
                            .getConnectionId();
            if (connectionId != null) {
                session.setConnectionId(connectionId);
                LOGGER.debug("ConnectionId: {}", session.getConnectionId().getValue());
            }
        }*/
    }

    private void prepareContentType(Session session) {
        session.setContentType(type.getValue());
        LOGGER.debug("ContentType: " + type.getValue());
        prepareContentMessageType(type);
    }

    private void prepareProtocolVersion(Session session) {
        /*if (chooser.getSelectedProtocolVersion().isTLS13()
                || sshContext.getActiveKeySetTypeWrite() == Tls13KeySetType.EARLY_TRAFFIC_SECRETS) {
            session.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        } else {
            session.setProtocolVersion(chooser.getSelectedProtocolVersion().getValue());
        }
        LOGGER.debug("ProtocolVersion: {}", session.getProtocolVersion().getValue());*/
    }

    private void prepareLength(Session session) {
        session.setLength(session.getProtocolMessageBytes().getValue().length);
        LOGGER.debug("Length: " + session.getLength().getValue());
    }

    protected void prepareContentMessageType(ProtocolMessageType type) {
        // getObject().setContentMessageType(this.type);
        LOGGER.debug("ContentMessageType: {}", type.getArrayValue());
    }
}
