package de.rub.nds.sshattacker.core.crypto.signature;

public class RawSignature {

    private SignatureAlgorithm signatureAlgorithm;

    private int signatureLength;
    private byte[] signatureBytes;

    public RawSignature() {}

    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(SignatureAlgorithm algorithm) {
        this.signatureAlgorithm = algorithm;
    }

    public int getSignatureLength() {
        return signatureLength;
    }

    public void setSignatureLength(int signatureLength) {
        this.signatureLength = signatureLength;
    }

    public byte[] getSignatureBytes() {
        return signatureBytes;
    }

    public void setSignatureBytes(byte[] signatureBytes) {
        this.signatureBytes = signatureBytes;
    }
}
