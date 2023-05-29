/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.session;

/*import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.*;
import de.rub.nds.tlsattacker.core.protocol.*;
import de.rub.nds.tlsattacker.core.record.compressor.RecordCompressor;
import de.rub.nds.tlsattacker.core.record.crypto.Encryptor;
import de.rub.nds.tlsattacker.core.record.parser.RecordParser;
import de.rub.nds.sshattacker.core.session.preparator.SessionPreparator;
import de.rub.nds.sshattacker.core.session.serializer.SessionSerializer;*/

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.sshattacker.core.constants.ProtocolMessageType;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.layer.data.DataContainer;
import de.rub.nds.sshattacker.core.layer.data.Handler;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.session.parser.SessionParser;
import de.rub.nds.sshattacker.core.session.preparator.SessionPreparator;
import de.rub.nds.sshattacker.core.session.serializer.SessionSerializer;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

public class Session extends ModifiableVariableHolder
        implements DataContainer<Session, SshContext> {

    /** maximum length configuration for this record */
    private Integer maxRecordLengthConfig;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.CIPHERTEXT)
    private ModifiableByteArray completeRecordBytes;

    /**
     * protocol message bytes transported in the record as seen on the transport layer if encryption
     * is active this is encrypted if not its plaintext
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.CIPHERTEXT)
    private ModifiableByteArray protocolMessageBytes;

    /** The decrypted , unpadded, unmaced record bytes */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PLAIN_PROTOCOL_MESSAGE)
    private ModifiableByteArray cleanProtocolMessageBytes;

    private ProtocolMessageType contentMessageType;

    /** Content type */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByte contentType;

    /** Record Layer Protocol Version */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray protocolVersion;

    /** total length of the protocol message (handshake, alert..) included in the record layer */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger length;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.COUNT)
    private ModifiableInteger epoch;

    /**
     * This is the implicit sequence number in TLS and also the explicit sequence number in DTLS
     * This could also have been a separate field within the computations struct but i chose to only
     * keep one of them as the whole situation is already complicated enough
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.COUNT)
    private ModifiableBigInteger sequenceNumber;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.NONE)
    private ModifiableByteArray connectionId;

    private SessionCryptoComputations computations;

    /*public Session(Config config) {
        this.maxRecordLengthConfig = config.getDefaultMaxRecordData();
    }*/

    public Session() {}

    public Session(Integer maxRecordLengthConfig) {
        this.maxRecordLengthConfig = maxRecordLengthConfig;
    }

    public ModifiableInteger getLength() {
        return length;
    }

    public ModifiableByte getContentType() {
        return contentType;
    }

    public ModifiableByteArray getProtocolVersion() {
        return protocolVersion;
    }

    public void setLength(ModifiableInteger length) {
        this.length = length;
    }

    public void setLength(int length) {
        this.length = ModifiableVariableFactory.safelySetValue(this.length, length);
    }

    public void setContentType(ModifiableByte contentType) {
        this.contentType = contentType;
    }

    public void setContentType(byte contentType) {
        this.contentType = ModifiableVariableFactory.safelySetValue(this.contentType, contentType);
    }

    public void setProtocolVersion(ModifiableByteArray protocolVersion) {
        this.protocolVersion = protocolVersion;
    }

    public void setProtocolVersion(byte[] array) {
        this.protocolVersion =
                ModifiableVariableFactory.safelySetValue(this.protocolVersion, array);
    }

    public ModifiableInteger getEpoch() {
        return epoch;
    }

    public void setEpoch(ModifiableInteger epoch) {
        this.epoch = epoch;
    }

    public void setEpoch(Integer epoch) {
        this.epoch = ModifiableVariableFactory.safelySetValue(this.epoch, epoch);
    }

    public ModifiableBigInteger getSequenceNumber() {
        return sequenceNumber;
    }

    public void setSequenceNumber(ModifiableBigInteger sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }

    public void setSequenceNumber(BigInteger sequenceNumber) {
        this.sequenceNumber =
                ModifiableVariableFactory.safelySetValue(this.sequenceNumber, sequenceNumber);
    }

    public ModifiableByteArray getConnectionId() {
        return connectionId;
    }

    public void setConnectionId(byte[] connectionId) {
        this.connectionId =
                ModifiableVariableFactory.safelySetValue(this.connectionId, connectionId);
    }

    public void setConnectionId(ModifiableByteArray connectionId) {
        this.connectionId = connectionId;
    }

    public SessionPreparator getSessionPreparator(
            SshContext sshContext,
            // Encryptor encryptor,
            // RecordCompressor compressor,
            ProtocolMessageType type) {
        return new SessionPreparator(sshContext, this, null /*type, compressor*/);
        // return new SessionPreparator(sshContext, this, encryptor /*type, compressor*/);
    }

    /*public SessionParser getSessionParser(
            InputStream stream, ProtocolVersion version, TlsContext tlsContext) {
        return new SessionParser(stream, version, tlsContext);
    }*/

    public SessionSerializer getSessionSerializer() {
        return new SessionSerializer(this);
    }

    /*public void adjustContext(SshContext sshContext) {
        ProtocolVersion version =
                ProtocolVersion.getProtocolVersion(getProtocolVersion().getValue());
        tlsContext.setLastRecordVersion(version);
    }*/

    public ProtocolMessageType getContentMessageType() {
        return contentMessageType;
    }

    public void setContentMessageType(ProtocolMessageType contentMessageType) {
        this.contentMessageType = contentMessageType;
    }

    public ModifiableByteArray getCleanProtocolMessageBytes() {
        return cleanProtocolMessageBytes;
    }

    public void setCleanProtocolMessageBytes(byte[] cleanProtocolMessageBytes) {
        this.cleanProtocolMessageBytes =
                ModifiableVariableFactory.safelySetValue(
                        this.cleanProtocolMessageBytes, cleanProtocolMessageBytes);
    }

    public void setCleanProtocolMessageBytes(ModifiableByteArray cleanProtocolMessageBytes) {
        this.cleanProtocolMessageBytes = cleanProtocolMessageBytes;
    }

    public ModifiableByteArray getProtocolMessageBytes() {
        return protocolMessageBytes;
    }

    public void setProtocolMessageBytes(ModifiableByteArray protocolMessageBytes) {
        this.protocolMessageBytes = protocolMessageBytes;
    }

    public void setProtocolMessageBytes(byte[] bytes) {
        this.protocolMessageBytes =
                ModifiableVariableFactory.safelySetValue(this.protocolMessageBytes, bytes);
    }

    public Integer getMaxRecordLengthConfig() {
        return maxRecordLengthConfig;
    }

    public void setMaxRecordLengthConfig(Integer maxRecordLengthConfig) {
        this.maxRecordLengthConfig = maxRecordLengthConfig;
    }

    public ModifiableByteArray getCompleteRecordBytes() {
        return completeRecordBytes;
    }

    public void setCompleteRecordBytes(ModifiableByteArray completeRecordBytes) {
        this.completeRecordBytes = completeRecordBytes;
    }

    public void setCompleteRecordBytes(byte[] completeRecordBytes) {
        this.completeRecordBytes =
                ModifiableVariableFactory.safelySetValue(
                        this.completeRecordBytes, completeRecordBytes);
    }

    public SessionCryptoComputations getComputations() {
        return computations;
    }

    public void setComputations(SessionCryptoComputations computations) {
        this.computations = computations;
    }

    public void prepareComputations() {
        if (computations == null) {
            this.computations = new SessionCryptoComputations();
        }
    }

    @Override
    public String toString() {
        return "Record{"
                + "contentType="
                + contentType
                + ", protocolVersion="
                + protocolVersion
                + ", length="
                + length
                + '}';
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 29 * hash + Objects.hashCode(this.contentType);
        hash = 29 * hash + Objects.hashCode(this.protocolVersion);
        hash = 29 * hash + Objects.hashCode(this.length);
        hash = 29 * hash + Objects.hashCode(this.epoch);
        hash = 29 * hash + Objects.hashCode(this.sequenceNumber);
        hash = 29 * hash + Objects.hashCode(this.connectionId);
        // hash = 29 * hash + Objects.hashCode(this.computations);
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
        final Session other = (Session) obj;
        if (!Objects.equals(this.contentType, other.contentType)) {
            return false;
        }
        if (!Objects.equals(this.protocolVersion, other.protocolVersion)) {
            return false;
        }
        if (!Objects.equals(this.length, other.length)) {
            return false;
        }
        if (!Objects.equals(this.epoch, other.epoch)) {
            return false;
        }
        if (!Objects.equals(this.sequenceNumber, other.sequenceNumber)) {
            return false;
        }
        if (!Objects.equals(this.connectionId, other.connectionId)) {
            return false;
        }
        /*if (!Objects.equals(this.computations, other.computations)) {
            return false;
        }*/
        return true;
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        /*if (computations != null) {
            holders.add(computations);
        }*/
        return holders;
    }

    @Override
    public void reset() {
        super.reset();
        setContentMessageType(null);
    }

    // TODO Fix this mess for records
    @Override
    public SessionParser getParser(SshContext context, InputStream stream) {
        return new SessionParser(context, stream);
    }

    @Override
    public SessionPreparator getPreparator(SshContext context) {
        // return new SessionPreparator(context, this, null, contentMessageType, null);
        return new SessionPreparator(context, this, null);
    }

    @Override
    public SessionSerializer getSerializer(SshContext context) {
        return new SessionSerializer(this);
    }

    @Override
    public Handler getHandler(SshContext sshContext) {
        throw new UnsupportedOperationException(
                "Not supported yet."); // To change body of generated methods, choose
        // Tools | Templates.
    }
}
