/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.EcPointFormat;
import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.sshattacker.core.crypto.keys.CustomCertEcdsaPublicKey;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.util.Map;


/** Serializer class to encode an ECDSA certificate public key (ecdsa-sha2-nistp256-cert-v01@openssh.com) format. */
public class CertEcdsaPublicKeySerializer extends Serializer<CustomCertEcdsaPublicKey> {

    private final CustomCertEcdsaPublicKey publicKey;
    private static final Logger LOGGER = LogManager.getLogger(CertEcdsaPublicKeySerializer.class);

    public CertEcdsaPublicKeySerializer(CustomCertEcdsaPublicKey publicKey) {
        super();
        this.publicKey = publicKey;
    }

    @Override
    protected void serializeBytes() {
        // Add debugging information before serialization
        LOGGER.debug("Starting serialization of CertEcdsaPublicKey.");
        LOGGER.debug("Curve Name: {}", publicKey.getCurveName());
        LOGGER.debug("Public Key: {}", publicKey.getWAsPoint());
        LOGGER.debug("Nonce: {}", publicKey.getNonce());
        LOGGER.debug("Signature Key: {}", publicKey.getSignatureKey());
        LOGGER.debug("Signature: {}", publicKey.getSignature());

        /*
         * The ecdsa-sha2-nistp256-cert-v01@openssh.com format as specified in the SSH protocol:
         *   string    "ecdsa-sha2-nistp256-cert-v01@openssh.com"
         *   string    nonce
         *   string    curve
         *   string    Q (the public key)
         *   uint64    serial
         *   uint32    type
         *   string    key id
         *   string    valid principals
         *   uint64    valid after
         *   uint64    valid before
         *   string    critical options
         *   string    extensions
         *   string    reserved
         *   string    signature key
         *   string    signature
         */

        // Format identifier (ecdsa-sha2-nistp256-cert-v01@openssh.com)
        appendInt(PublicKeyFormat.ECDSA_SHA2_NISTP256_CERT_V01_OPENSSH_COM.toString().getBytes(StandardCharsets.US_ASCII).length, DataFormatConstants.STRING_SIZE_LENGTH);
        appendString(PublicKeyFormat.ECDSA_SHA2_NISTP256_CERT_V01_OPENSSH_COM.toString(), StandardCharsets.US_ASCII);

        // Nonce
        byte[] nonce = publicKey.getNonce();
        appendInt(nonce.length, DataFormatConstants.STRING_SIZE_LENGTH);
        appendBytes(nonce);

        // Curve name
        String curveName = publicKey.getCurveName();
        appendInt(curveName.getBytes(StandardCharsets.US_ASCII).length, DataFormatConstants.STRING_SIZE_LENGTH);
        appendString(curveName, StandardCharsets.US_ASCII);

        // Public Key (Q)
        byte[] encodedQ = PointFormatter.formatToByteArray(publicKey.getGroup(), publicKey.getWAsPoint(), EcPointFormat.UNCOMPRESSED);
        appendInt(encodedQ.length, DataFormatConstants.STRING_SIZE_LENGTH);
        appendBytes(encodedQ);

        // Serial (uint64)
        appendBigInteger(BigInteger.valueOf(publicKey.getSerial()), DataFormatConstants.UINT64_SIZE);

        // Certificate type (uint32)
        appendInt(Integer.parseInt(publicKey.getCertType()), DataFormatConstants.UINT32_SIZE);

        // Key ID (string)
        String keyId = publicKey.getKeyId();
        appendInt(keyId.getBytes(StandardCharsets.US_ASCII).length, DataFormatConstants.STRING_SIZE_LENGTH);
        appendString(keyId, StandardCharsets.US_ASCII);

        // Valid Principals (string list)
        String[] validPrincipals = publicKey.getValidPrincipals();
        if (validPrincipals != null && validPrincipals.length > 0) {
            // Append each principal as separate SSH strings, according to SSH format expectations
            ByteBuffer principalsBuffer = ByteBuffer.allocate(1024); // Initial buffer size; grows dynamically if needed
            for (String principal : validPrincipals) {
                byte[] principalBytes = principal.getBytes(StandardCharsets.US_ASCII);
                // Serialize each principal with length prefix
                principalsBuffer.putInt(principalBytes.length);
                principalsBuffer.put(principalBytes);
            }
            byte[] principalsSerialized = new byte[principalsBuffer.position()];
            principalsBuffer.flip();
            principalsBuffer.get(principalsSerialized);

            appendInt(principalsSerialized.length, DataFormatConstants.STRING_SIZE_LENGTH);
            appendBytes(principalsSerialized);
        } else {
            appendInt(0, DataFormatConstants.STRING_SIZE_LENGTH); // Empty principals list
        }

        // Valid After (uint64)
        appendBigInteger(BigInteger.valueOf(publicKey.getValidAfter()), DataFormatConstants.UINT64_SIZE);

        // Valid Before (uint64)
        appendBigInteger(BigInteger.valueOf(publicKey.getValidBefore()), DataFormatConstants.UINT64_SIZE);

        // Critical Options
        Map<String, String> criticalOptions = publicKey.getCriticalOptions();
        appendStringMap(criticalOptions);

        // Extensions
        Map<String, String> extensions = publicKey.getExtensions();
        appendStringMap(extensions);

        // Reserved
        String reserved = publicKey.getReserved();
        if (reserved != null) {
            byte[] reservedBytes = reserved.getBytes(StandardCharsets.US_ASCII);
            appendInt(reservedBytes.length, DataFormatConstants.STRING_SIZE_LENGTH);
            appendBytes(reservedBytes);
        } else {
            appendInt(0, DataFormatConstants.STRING_SIZE_LENGTH);
        }

        // Signature Key
        byte[] signatureKey = publicKey.getSignatureKey();
        if (signatureKey == null) {
            throw new IllegalStateException("Signature Key is not set in the publicKey");
        }
        appendInt(signatureKey.length, DataFormatConstants.STRING_SIZE_LENGTH);
        appendBytes(signatureKey);

        // Signature
        byte[] signature = publicKey.getSignature();
        if (signature == null) {
            throw new IllegalStateException("Signature is not set in the publicKey");
        }
        appendInt(signature.length, DataFormatConstants.STRING_SIZE_LENGTH);
        appendBytes(signature);
    }

    private void appendStringMap(Map<String, String> stringMap) {
        if (stringMap != null && !stringMap.isEmpty()) {
            StringBuilder optionsBuilder = new StringBuilder();
            for (Map.Entry<String, String> entry : stringMap.entrySet()) {
                optionsBuilder.append(serializeString(entry.getKey()));
                optionsBuilder.append(serializeString(entry.getValue()));
            }
            byte[] optionsBytes = optionsBuilder.toString().getBytes(StandardCharsets.US_ASCII);
            appendInt(optionsBytes.length, DataFormatConstants.STRING_SIZE_LENGTH);
            appendBytes(optionsBytes);
        } else {
            appendInt(0, DataFormatConstants.STRING_SIZE_LENGTH); // Leeres Feld, wenn die Map leer ist
        }
    }
    private static String serializeString(String value) {
        byte[] valueBytes = value.getBytes(StandardCharsets.US_ASCII);
        return buildStringWithLength(valueBytes);
    }
    private static String buildStringWithLength(byte[] valueBytes) {
        return new String(ByteBuffer.allocate(DataFormatConstants.STRING_SIZE_LENGTH).putInt(valueBytes.length).array())
                + new String(valueBytes, StandardCharsets.US_ASCII);
    }
}
