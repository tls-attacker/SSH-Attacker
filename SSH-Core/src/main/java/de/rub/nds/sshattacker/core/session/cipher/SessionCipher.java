/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.session.cipher;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.ProtocolMessageType;
import de.rub.nds.sshattacker.core.crypto.cipher.DecryptionCipher;
import de.rub.nds.sshattacker.core.crypto.cipher.EncryptionCipher;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.layer.data.Parser;
import de.rub.nds.sshattacker.core.session.Session;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SessionCipher {

    private static final Logger LOGGER = LogManager.getLogger();

    public static final byte[] SEQUENCE_NUMBER_PLACEHOLDER =
            new byte[] {
                (byte) 0xFF,
                (byte) 0xFF,
                (byte) 0xFF,
                (byte) 0xFF,
                (byte) 0xFF,
                (byte) 0xFF,
                (byte) 0xFF,
                (byte) 0xFF
            };

    /** cipher for decryption */
    protected DecryptionCipher decryptCipher;

    /** cipher for encryption */
    protected EncryptionCipher encryptCipher;

    /** TLS context */
    protected SshContext sshContext;

    /** cipher state */
    private CipherState state;

    public SessionCipher(SshContext sshContext, CipherState state) {
        this.sshContext = sshContext;
        this.state = state;
    }

    public abstract void encrypt(Session session) throws CryptoException;

    public abstract void decrypt(Session session) throws CryptoException;

    /**
     * This function collects data needed for computing MACs and other authentication tags in
     * CBC/CCM/GCM cipher suites.
     *
     * <p>From the Lucky13 paper: An individual record R (viewed as a byte sequence of length at
     * least zero) is processed as follows. The sender maintains an 8-byte sequence number SQN which
     * is incremented for each record sent, and forms a 5-byte field HDR consisting of a 1-byte type
     * field, a 2-byte version field, and a 2-byte length field. It then calculates a MAC over the
     * bytes SQN || HDR || R.
     *
     * @param session The Record for which the data should be collected //@param protocolVersion
     *     According to which ProtocolVersion the AdditionalAuthenticationData is collected
     * @return The AdditionalAuthenticatedData
     */
    protected final byte[] collectAdditionalAuthenticatedData(Session session) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        /*try {
            if (protocolVersion.isTLS13()) {
                stream.write(record.getContentType().getValue());
                stream.write(record.getProtocolVersion().getValue());
                if (record.getLength() != null && record.getLength().getValue() != null) {
                    stream.write(
                            ArrayConverter.intToBytes(
                                    record.getLength().getValue(), RecordByteLength.RECORD_LENGTH));
                } else {
                    // It may happen that the record does not have a length prepared - in that case
                    // we will need to add
                    // the length of the data content
                    // This is mostly interessting for fuzzing
                    stream.write(
                            ArrayConverter.intToBytes(
                                    record.getCleanProtocolMessageBytes().getValue().length,
                                    RecordByteLength.RECORD_LENGTH));
                }
                return stream.toByteArray();
            } else {
                if (protocolVersion.isDTLS()) {
                    if (ProtocolMessageType.getContentType(record.getContentType().getValue())
                            == ProtocolMessageType.TLS12_CID) {
                        stream.write(SEQUENCE_NUMBER_PLACEHOLDER);
                        stream.write(ProtocolMessageType.TLS12_CID.getValue());
                        stream.write(record.getConnectionId().getValue().length);
                    } else {
                        stream.write(
                                ArrayConverter.intToBytes(
                                        record.getEpoch().getValue().shortValue(),
                                        RecordByteLength.DTLS_EPOCH));
                        stream.write(
                                ArrayConverter.longToUint48Bytes(
                                        record.getSequenceNumber().getValue().longValue()));
                    }
                } else {
                    stream.write(
                            ArrayConverter.longToUint64Bytes(
                                    record.getSequenceNumber().getValue().longValue()));
                }
                stream.write(record.getContentType().getValue());
                byte[] version;
                if (!protocolVersion.isSSL()) {
                    version = record.getProtocolVersion().getValue();
                } else {
                    version = new byte[0];
                }
                stream.write(version);
                if (protocolVersion.isDTLS()
                        && ProtocolMessageType.getContentType(record.getContentType().getValue())
                                == ProtocolMessageType.TLS12_CID) {
                    stream.write(
                            ArrayConverter.intToBytes(
                                    record.getEpoch().getValue().shortValue(),
                                    RecordByteLength.DTLS_EPOCH));
                    stream.write(
                            ArrayConverter.longToUint48Bytes(
                                    record.getSequenceNumber().getValue().longValue()));
                    stream.write(record.getConnectionId().getValue());
                }
                int length;
                if (record.getComputations().getAuthenticatedNonMetaData() == null
                        || record.getComputations().getAuthenticatedNonMetaData().getOriginalValue()
                                == null) {
                    // This case is required for TLS 1.2 aead encryption
                    length = record.getComputations().getPlainRecordBytes().getValue().length;
                } else {
                    length =
                            record.getComputations()
                                    .getAuthenticatedNonMetaData()
                                    .getValue()
                                    .length;
                }
                stream.write(ArrayConverter.intToBytes(length, RecordByteLength.RECORD_LENGTH));
                return stream.toByteArray();
            }
        } catch (IOException e) {
            throw new WorkflowExecutionException("Could not write data to ByteArrayOutputStream");
        }*/

        return null;
    }

    /**
     * Reads a byte array from the end, and counts how many 0x00 bytes there are, until the first
     * non-zero byte appears
     *
     * @param plainRecordBytes the byte array to count from
     * @return number of trailing 0x00 bytes
     */
    private int countTrailingZeroBytes(byte[] plainRecordBytes) {
        int counter = 0;
        for (int i = plainRecordBytes.length - 1; i < plainRecordBytes.length; i--) {
            if (plainRecordBytes[i] == 0) {
                counter++;
            } else {
                return counter;
            }
        }
        return counter;
    }

    /**
     * Encapsulate plain record bytes as TLS 1.3 application data or DTLS 1.2 ConnectionID data
     * container. Construction: CleanBytes | ContentType | 0x00000... (Padding)
     *
     * @param session the record which is affected
     * @return the encapsulated data
     */
    protected byte[] encapsulateRecordBytes(Session session) {
        byte[] padding =
                session.getComputations().getPadding() != null
                        ? session.getComputations().getPadding().getValue()
                        : new byte[0];
        return ArrayConverter.concatenate(
                session.getCleanProtocolMessageBytes().getValue(),
                new byte[] {session.getContentType().getValue()},
                padding);
    }

    /**
     * Read plain record bytes that are encapsuled as either TLS 1.3 application data or DTLS 1.2
     * ConnectionID data. Construction: CleanBytes | ContentType | 0x00000... (Padding)
     *
     * @param plainRecordBytes the plain encapsulated record bytes
     * @param session the record which is affected
     */
    protected void parseEncapsulatedRecordBytes(byte[] plainRecordBytes, Session session) {
        int numberOfPaddingBytes = countTrailingZeroBytes(plainRecordBytes);
        if (numberOfPaddingBytes == plainRecordBytes.length) {
            LOGGER.warn(
                    "Record contains ONLY padding and no content type. Setting clean bytes == plainbytes");
            session.setCleanProtocolMessageBytes(plainRecordBytes);
            return;
        }
        PlaintextParser parser = new PlaintextParser(plainRecordBytes);
        byte[] cleanBytes =
                parser.parseByteArrayField(plainRecordBytes.length - numberOfPaddingBytes - 1);
        byte[] contentType = parser.parseByteArrayField(1);
        byte[] padding = parser.parseByteArrayField(numberOfPaddingBytes);
        session.getComputations().setPadding(padding);
        session.setCleanProtocolMessageBytes(cleanBytes);
        session.setContentType(contentType[0]);
        session.setContentMessageType(ProtocolMessageType.getContentType(contentType[0]));
    }

    public CipherState getState() {
        return state;
    }

    public void setState(CipherState state) {
        this.state = state;
    }

    public ConnectionEndType getLocalConnectionEndType() {
        return sshContext.getContext().getConnection().getLocalConnectionEndType();
    }

    public ConnectionEndType getConnectionEndType() {
        return sshContext.getChooser().getConnectionEndType();
    }

    public Integer getDefaultAdditionalPadding() {
        return sshContext.getConfig().getDefaultAdditionalPadding();
    }

    public ConnectionEndType getTalkingConnectionEndType() {
        return sshContext.getTalkingConnectionEndType();
    }

    public Random getRandom() {
        return sshContext.getRandom();
    }

    class PlaintextParser extends Parser<Object> {

        public PlaintextParser(byte[] array) {
            super(new ByteArrayInputStream(array));
        }

        @Override
        public void parse(Object t) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public byte[] parseByteArrayField(int length) {
            return super.parseByteArrayField(length);
        }

        @Override
        public int getBytesLeft() {
            return super.getBytesLeft();
        }
    }
}
