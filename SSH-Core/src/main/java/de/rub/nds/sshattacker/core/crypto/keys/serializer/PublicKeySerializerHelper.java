/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;

public final class PublicKeySerializerHelper {

    private PublicKeySerializerHelper() {
        super();
    }

    public static void appendStringMap(Map<String, String> stringMap, SerializerStream output) {
        if (stringMap != null && !stringMap.isEmpty()) {
            SerializerStream optionsBuilder = new SerializerStream();
            for (Map.Entry<String, String> entry : stringMap.entrySet()) {
                optionsBuilder.appendInt(
                        entry.getKey().getBytes(StandardCharsets.US_ASCII).length,
                        DataFormatConstants.STRING_SIZE_LENGTH);
                optionsBuilder.appendString(entry.getKey(), StandardCharsets.US_ASCII);
                optionsBuilder.appendInt(
                        entry.getValue().getBytes(StandardCharsets.US_ASCII).length,
                        DataFormatConstants.STRING_SIZE_LENGTH);
                optionsBuilder.appendString(entry.getValue(), StandardCharsets.US_ASCII);
            }
            byte[] optionsBytes = optionsBuilder.toByteArray();
            output.appendInt(optionsBytes.length, DataFormatConstants.STRING_SIZE_LENGTH);
            output.appendBytes(optionsBytes);
        } else {
            output.appendInt(
                    0, DataFormatConstants.STRING_SIZE_LENGTH); // Empty string, if the map is empty
        }
    }

    /** Utility method to serialize Distinguished Names (DN) in ASN.1 format using BouncyCastle. */
    public static ASN1Sequence getDistinguishedNameAsASN1(
            String dn, boolean reverseDistinguishedName) {
        if (dn != null && !dn.isEmpty()) {
            try {
                if (reverseDistinguishedName) {
                    dn = reverseDistinguishedName(dn);
                }
                X500Name x500Name = new X500Name(dn);
                return (ASN1Sequence) x500Name.toASN1Primitive();
            } catch (Exception e) {
                throw new RuntimeException("Error encoding Distinguished Name", e);
            }
        } else {
            throw new IllegalArgumentException("Distinguished Name cannot be null or empty");
        }
    }

    /** Helper method to reverse the order of Distinguished Name components. */
    private static String reverseDistinguishedName(String dn) {
        String[] parts = dn.split(",");
        int len = parts.length;
        StringBuilder reversed = new StringBuilder(dn.length());

        for (int i = len - 1; i >= 0; i--) {
            reversed.append(parts[i].trim());
            if (i > 0) {
                reversed.append(",");
            }
        }
        return reversed.toString();
    }

    /** Utility method to serialize validity period as ASN.1 GeneralizedTime. */
    public static ASN1Sequence getValidityPeriodAsASN1(long validAfter, long validBefore) {
        try {
            DateTimeFormatter dateTimeFormatter =
                    DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
            String validAfterStr = dateTimeFormatter.format(Instant.ofEpochSecond(validAfter));
            String validBeforeStr = dateTimeFormatter.format(Instant.ofEpochSecond(validBefore));

            ASN1EncodableVector validityVector = new ASN1EncodableVector();
            validityVector.add(new ASN1GeneralizedTime(validAfterStr));
            validityVector.add(new ASN1GeneralizedTime(validBeforeStr));

            return new DERSequence(validityVector);
        } catch (Exception e) {
            throw new RuntimeException("Error encoding Validity Period", e);
        }
    }

    /** Utility method to parse the extension value which could be a hex string or a raw string. */
    public static byte[] parseExtensionValue(String value) {
        if (value.startsWith("[")) {
            // Assuming value is in byte array format [4, 22, ...]
            value = value.replaceAll("[\\[\\]\\s]", "");
            String[] byteValues = value.split(",");
            byte[] data = new byte[byteValues.length];
            for (int i = 0; i < byteValues.length; i++) {
                data[i] = Byte.parseByte(byteValues[i]);
            }
            return data;
        } else {
            // Assuming value is a hex string
            return hexStringToByteArray(value);
        }
    }

    /** Utility method to convert hex string to byte array. */
    private static byte[] hexStringToByteArray(String s) {
        if (s.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have an even length");
        }
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] =
                    (byte)
                            ((Character.digit(s.charAt(i), 16) << 4)
                                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
