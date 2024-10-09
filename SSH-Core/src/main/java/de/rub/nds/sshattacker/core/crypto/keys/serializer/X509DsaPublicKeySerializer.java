package de.rub.nds.sshattacker.core.crypto.keys.serializer;

import de.rub.nds.sshattacker.core.crypto.keys.CustomX509DsaPublicKey;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;

import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;

/**
 * Serializer class to encode a DSA X.509 public key (X509-SSH-DSA) format.
 */
public class X509DsaPublicKeySerializer extends Serializer<CustomX509DsaPublicKey> {

    private final CustomX509DsaPublicKey publicKey;

    public X509DsaPublicKeySerializer(CustomX509DsaPublicKey publicKey) {
        super();
        this.publicKey = publicKey;
    }

    @Override
    protected void serializeBytes() {
        /*
         * The X509-SSH-DSA format as specified in the SSH protocol:
         *   uint32    version
         *   uint64    serial
         *   string    signature algorithm
         *   string    issuer (Distinguished Name - DN)
         *   uint64    valid after
         *   uint64    valid before
         *   string    subject (Distinguished Name - DN)
         *   string    public key algorithm
         *   mpint     y (DSA public key)
         *   string    extensions
         *   string    signature
         */

        try {
            ASN1EncodableVector topLevelVector = new ASN1EncodableVector();

            // Version (uint32) as ASN.1 INTEGER
            topLevelVector.add(new org.bouncycastle.asn1.ASN1Integer(publicKey.getVersion()));

            // Serial (uint64) as ASN.1 INTEGER
            topLevelVector.add(new org.bouncycastle.asn1.ASN1Integer(BigInteger.valueOf(publicKey.getSerial())));

            // Signature Algorithm (SHA256withDSA as OID in ASN.1 format with NULL parameter)
            AlgorithmIdentifier signatureAlgorithm = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.10040.4.3"), DERNull.INSTANCE); // OID for sha256WithDSAEncryption
            topLevelVector.add(signatureAlgorithm);

            // Issuer (Distinguished Name in ASN.1 format)
            ASN1Sequence issuerSequence = getDistinguishedNameAsASN1(publicKey.getIssuer());
            topLevelVector.add(issuerSequence);

            // Validity Period (ASN.1 GeneralizedTime for Not Before and Not After)
            ASN1Sequence validitySequence = getValidityPeriodAsASN1(publicKey.getValidAfter(), publicKey.getValidBefore());
            topLevelVector.add(validitySequence);

            // Subject (Distinguished Name in ASN.1 format)
            ASN1Sequence subjectSequence = getDistinguishedNameAsASN1(publicKey.getSubject());
            topLevelVector.add(subjectSequence);

            // Public Key Algorithm (OID for DSA with NULL parameter)
            AlgorithmIdentifier publicKeyAlgorithm = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.10040.4.1"), DERNull.INSTANCE); // OID for DSA
            topLevelVector.add(publicKeyAlgorithm);

            // DSA Public Key 'y' (as ASN.1 INTEGER)
            topLevelVector.add(new org.bouncycastle.asn1.ASN1Integer(publicKey.getY()));

            // Extensions (ASN.1 encoded as Extensions sequence)
            Extensions extensions = getExtensionsAsASN1(publicKey.getExtensions());
            if (extensions != null) {
                topLevelVector.add(extensions);
            }

            // Signature (string) as ASN.1 OctetString
            byte[] signature = publicKey.getSignature();
            if (signature == null) {
                throw new IllegalStateException("Signature is not set in the publicKey");
            }
            topLevelVector.add(new DEROctetString(signature));

            // Serialize the entire ASN.1 structure
            ASN1Sequence topLevelSequence = new DERSequence(topLevelVector);
            byte[] asn1Encoded = topLevelSequence.getEncoded();
            appendBytes(asn1Encoded);

        } catch (Exception e) {
            throw new RuntimeException("Error serializing X509 DSA Public Key", e);
        }
    }

    /**
     * Utility method to serialize Distinguished Names (DN) in ASN.1 format using BouncyCastle.
     */
    private ASN1Sequence getDistinguishedNameAsASN1(String dn) {
        if (dn != null && !dn.isEmpty()) {
            try {
                X500Name x500Name = new X500Name(dn);
                return (ASN1Sequence) x500Name.toASN1Primitive();
            } catch (Exception e) {
                throw new RuntimeException("Error encoding Distinguished Name", e);
            }
        } else {
            throw new IllegalArgumentException("Distinguished Name cannot be null or empty");
        }
    }

    /**
     * Utility method to serialize validity period as ASN.1 GeneralizedTime.
     */
    private ASN1Sequence getValidityPeriodAsASN1(long validAfter, long validBefore) {
        try {
            SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
            String validAfterStr = dateFormat.format(new Date(validAfter * 1000));
            String validBeforeStr = dateFormat.format(new Date(validBefore * 1000));

            ASN1GeneralizedTime notBefore = new ASN1GeneralizedTime(validAfterStr);
            ASN1GeneralizedTime notAfter = new ASN1GeneralizedTime(validBeforeStr);

            ASN1EncodableVector validityVector = new ASN1EncodableVector();
            validityVector.add(notBefore);
            validityVector.add(notAfter);

            return new DERSequence(validityVector);
        } catch (Exception e) {
            throw new RuntimeException("Error encoding Validity Period", e);
        }
    }

    /**
     * Utility method to serialize extensions as ASN.1 Extensions.
     */
    private Extensions getExtensionsAsASN1(Map<String, String> extensionsMap) {
        if (extensionsMap != null && !extensionsMap.isEmpty()) {
            try {
                ASN1EncodableVector extensionsVector = new ASN1EncodableVector();
                for (Map.Entry<String, String> entry : extensionsMap.entrySet()) {
                    String key = entry.getKey();
                    ASN1ObjectIdentifier oid;
                    DEROctetString value;

                    switch (key) {
                        case "SubjectKeyIdentifier":
                            oid = Extension.subjectKeyIdentifier;
                            value = new DEROctetString(parseExtensionValue(entry.getValue()));
                            break;
                        case "AuthorityKeyIdentifier":
                            oid = Extension.authorityKeyIdentifier;
                            value = new DEROctetString(parseExtensionValue(entry.getValue()));
                            break;
                        default:
                            throw new IllegalArgumentException("Unsupported extension key: " + key);
                    }

                    Extension extension = new Extension(oid, false, value);
                    extensionsVector.add(extension);
                }
                return Extensions.getInstance(new DERSequence(extensionsVector));
            } catch (Exception e) {
                throw new RuntimeException("Error encoding Extensions", e);
            }
        }
        return null;
    }

    /**
     * Utility method to parse the extension value which could be a hex string or a raw string.
     */
    private byte[] parseExtensionValue(String value) {
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

    /**
     * Utility method to convert hex string to byte array.
     */
    private byte[] hexStringToByteArray(String s) {
        if (s.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have an even length");
        }
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
