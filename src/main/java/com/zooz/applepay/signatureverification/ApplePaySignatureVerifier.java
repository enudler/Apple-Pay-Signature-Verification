package com.zooz.applepay.signatureverification;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.*;
import java.util.*;

// Validating apple pay signature according to
// https://developer.apple.com/library/prerelease/ios/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html
public class ApplePaySignatureVerifier {

    private static final String APPLE_ROOT_CA_G3_CER = "AppleRootCA-G3.cer";
    private static final String BC = "BC";
    private static final String LEAF_OID = "1.2.840.113635.100.6.29";
    private static final String INTERMEDIATE_OID = "1.2.840.113635.100.6.2.14";
    private static final String PKIX = "PKIX";
    private static final String COLLECTION = "Collection";
    private static final String X_509 = "X.509";

    public static void validate(String applePayData, ApplePayPaymentHeader applePayHeader,
                                String applePaySignature, long applePaySignatureExpirationInMs) throws Exception {

        byte[] signedData = getSignedData(applePayData, applePayHeader);
        CMSSignedData cmsSignedData = new CMSSignedData(new CMSProcessableByteArray(signedData), Base64.decode(applePaySignature));

        Store store = cmsSignedData.getCertificates();
        ArrayList<X509CertificateHolder> allCertificates = (ArrayList<X509CertificateHolder>) store.getMatches(null);
        ArrayList signers = (ArrayList) cmsSignedData.getSignerInfos().getSigners();
        SignerInformation signerInformation = (SignerInformation) signers.get(0);

        List<X509Certificate> x509Certificates = new ArrayList();
        for (X509CertificateHolder certificate : allCertificates) {
            x509Certificates.add(new JcaX509CertificateConverter().setProvider(BC).getCertificate(certificate));
        }

        // step 1:
        // Ensure that the certificates contain the correct custom OIDs: 1.2.840.113635.100.6.29
        // for the leaf certificate and 1.2.840.113635.100.6.2.14 for the intermediate CA. The value for these marker OIDs doesn’t matter, only their presence.
        validateCustomData(allCertificates);

        InputStream inputStream = null;
        X509Certificate appleRootCertificate = null;
        // step 2:
        // Ensure that the root CA is the Apple Root CA - G3. This certificate is available from apple.com/certificateauthority.
        try {
            inputStream = ApplePaySignatureVerifier.class.getClassLoader().getResourceAsStream(APPLE_ROOT_CA_G3_CER);
            CertificateFactory certificateFactory = CertificateFactory.getInstance(X_509);
            appleRootCertificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
        } finally {
            IOUtils.closeQuietly(inputStream);
        }

        // step 3:
        // Ensure that there is a valid X.509 chain of trust from the signature to the root CA. Specifically,
        // ensure that the signature was created using the private key corresponding to the leaf certificate,
        // that the leaf certificate is signed by the intermediate CA, and that the intermediate CA is signed by the Apple Root CA - G3.
        verifyCertificate(x509Certificates.get(0), appleRootCertificate, x509Certificates);

        // step 4:
        // Ensure that the signature is a valid ECDSA signature (ecdsa-with-SHA256 1.2.840.10045.4.3.2) of the
        // concatenated values of the ephemeralPublicKey, data, transactionId, and applicationData keys.
        validateSignature(signerInformation, store);

        // step 5:
        // Inspect the CMS signing time of the signature, as defined by section 11.3 of RFC 5652.
        // If the time signature and the transaction time differ by more than a few minutes, it's possible that the token is a replay attack.
        validateSignatureTime(applePaySignatureExpirationInMs, signerInformation);
    }

    private static void validateCustomData(ArrayList<X509CertificateHolder> allCertificates) throws Exception {

        if (allCertificates.size() != 2) {
            throw new Exception("signature certificates count expected 2, but it's :" + allCertificates.size());
        }
        if (allCertificates.get(0).getExtension(new ASN1ObjectIdentifier(LEAF_OID)) == null) {
            throw new Exception("leaf certificate doesn't have extension: " + LEAF_OID);
        }
        if (allCertificates.get(1).getExtension(new ASN1ObjectIdentifier(INTERMEDIATE_OID)) == null) {
            throw new Exception("intermediate certificate doesn't have extension: " + INTERMEDIATE_OID);
        }
    }

    private static void validateSignature(SignerInformation signerInformation, Store store) throws Exception {

        try {
            ArrayList certCollection = (ArrayList) store.getMatches(signerInformation.getSID());
            Iterator certIt = certCollection.iterator();
            X509CertificateHolder certHolder = (X509CertificateHolder) certIt.next();
            X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certHolder);
            signerInformation.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert));
        } catch (Exception ex) {
            throw new Exception("Failed to verify apple pay signature, the result is false");
        }
    }

    private static void validateSignatureTime(long applePaySignatureExpirationInMs, SignerInformation signerInformation) throws Exception {
        long signDate = 0;
        AttributeTable signedAttributes = signerInformation.getSignedAttributes();
        Attribute signingTime = signedAttributes.get(CMSAttributes.signingTime);
        Enumeration signingTimeObjects = signingTime.getAttrValues().getObjects();
        if (signingTimeObjects.hasMoreElements()) {
            Object signingTimeObject = signingTimeObjects.nextElement();
            if (signingTimeObject instanceof ASN1UTCTime) {
                ASN1UTCTime asn1Time = (ASN1UTCTime) signingTimeObject;
                signDate = asn1Time.getDate().getTime();
            }
        }
        if (signDate == 0) {
            throw new Exception("Failed to extract sign time from apple pay signature.");
        }

        long expiration = System.currentTimeMillis() - applePaySignatureExpirationInMs;
        if (expiration > signDate) {
            throw new Exception("apple pay signature is too old, the expiration time is: " + applePaySignatureExpirationInMs + " ms");
        }
    }

    private static void verifyCertificate(X509Certificate leafCertificate, X509Certificate trustedRootCert,
                                                               List<X509Certificate> intermediateCerts) throws Exception {
        try {
            // Create the selector that specifies the starting certificate
            X509CertSelector selector = new X509CertSelector();
            selector.setCertificate(leafCertificate);

            // Create the trust anchors (set of root CA certificates)
            Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
            trustAnchors.add(new TrustAnchor(trustedRootCert, null));

            // Configure the PKIX certificate builder algorithm parameters
            PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(trustAnchors, selector);

            // Disable CRL checks (this is done manually as additional step)
            pkixParams.setRevocationEnabled(false);

            // Specify a list of intermediate certificates
            CertStore intermediateCertStore = CertStore.getInstance(COLLECTION, new CollectionCertStoreParameters(intermediateCerts), BC);
            pkixParams.addCertStore(intermediateCertStore);

            // Build and verify the certification chain
            CertPathBuilder builder = CertPathBuilder.getInstance(PKIX, BC);

            //If no exception thrown, it means the validation passed.
            PKIXCertPathBuilderResult pkixCertPathBuilderResult = (PKIXCertPathBuilderResult) builder.build(pkixParams);

        } catch (Exception ex) {
            throw new Exception("Failed to validate chain of trust for apple certificates.");
        }
    }

    private static byte[] getSignedData(String applePayData, ApplePayPaymentHeader applePayHeader) throws IOException {
        byte[] ephemeralPublicKeyBytes = Base64.decode(applePayHeader.getEphemeralPublicKey());
        byte[] applePayDataBytes = Base64.decode(applePayData);
        byte[] transactionIdBytes = Hex.decode(applePayHeader.getTransactionId());
        byte[] applicationDataBytes = null;
        if (!StringUtils.isEmpty(applePayHeader.getApplicationData())) {
            applicationDataBytes = Hex.decode(applePayHeader.getApplicationData());
        }

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.write(ephemeralPublicKeyBytes);
        byteArrayOutputStream.write(applePayDataBytes);
        byteArrayOutputStream.write(transactionIdBytes);
        if (applicationDataBytes != null) {
            byteArrayOutputStream.write(applicationDataBytes);
        }

        return byteArrayOutputStream.toByteArray();
    }
}
