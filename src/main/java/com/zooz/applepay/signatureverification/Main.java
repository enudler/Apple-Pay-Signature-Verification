package com.zooz.applepay.signatureverification;

import com.google.gson.Gson;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;

import java.util.*;

/**
 * Example implementation of Apple Pay signature verification
 */
public class Main {

    //Replace this with your data, as this one is corrupted for security reasons.
    private static final String paymentJsonData = "{\"version\":\"EC_v1\",\"data\":\"tUxc4JQzfya5gRy/kBvkJX+fT4GfkUWrHf8XlaCrSlS5XsQnOKQsdW9ddtIcp7WQ0h6Im164tWOcRbq8s5/chjJJ/5YVx5ZgU1UDk0B1Qh6658kISxWuKrWsuiDH3sLe0kUwxlKobruZ4IGCCPPlf0EOhllHtQ0XTKQhMZBwhEcCxsw5TbEp2rWo+et8H/Fi+osJDEJyPevroGg3zRC9w6mH2q1EsJQZVvT1gz52xt0wpdeQDN393I3uAuYmmnsV8Y8ulaYSzkZvKiZomr63e3CFdHDIT3dswNoWsKdWxDBVUoU9fAHAxzAgquqXPr0u5lQSYj9xAQL80Tatl2UE1YGz54N08o3BoRGdVqJFq6QfFKWNIEKPOOLwcodrii9Ib8fZyTMzCLL8swx/i/2D619W5fhC/t3kTguSvvFA==\",\"signature\":\"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\",\"header\":{\"transactionId\":\"04880455baf67a1f9f603f2a773423e836281b22085222420805bb0cee7005\",\"ephemeralPublicKey\":\"MFkwEwYHKoIzj0CAQYIKoZIzj0DAQcDQgAEWiDMpOVfLD3g2lYsapLGK0GiYBptZx3Pj/sCr/TpobNdtgVxH+YdPJNYPh5u3UH9ZQYuefIwBXIFhGysM4OUQ==\",\"publicKeyHash\":\"ruwsupEHrrVuBV83LRb6l+BycmzpojSil5EzxwbmjM=\"}}";
    private static final String BC = "BC";
    private static final String EC_V_1 = "EC_v1";
    private static final String HEADER = "header";
    private static final String APPLICATION_DATA = "applicationData";
    private static final String APPLICATION_DATA1 = "applicationData";
    private static final String EPHEMERAL_PUBLIC_KEY = "ephemeralPublicKey";
    private static final String PUBLIC_KEY_HASH = "publicKeyHash";
    private static final String TRANSACTION_ID = "transactionId";
    private static final String DATA = "data";
    private static final String SIGNATURE = "signature";
    private static final String VERSION = "version";
    private static final int APPLE_PAY_SIGNATURE_EXPIRATION_IN_MS = 60000;


    public static void main(String[] args) throws Exception {

        if (Security.getProvider(BC) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        Map paymentToken = new Gson().fromJson(paymentJsonData, Map.class);
        ApplePayPaymentHeader applePayPaymentHeader = CreateApplePayPaymentHeader(paymentToken);
        String applePayData = paymentToken.get(DATA).toString();
        String applePaySignature = paymentToken.get(SIGNATURE).toString();
        String applePayVersion = paymentToken.get(VERSION).toString();

        if (!applePayVersion.equals(EC_V_1)) {
            throw new Exception("Apple pay signature verification supported only for version " + EC_V_1);
        }

        ApplePaySignatureVerifier.validate(applePayData, applePayPaymentHeader, applePaySignature, APPLE_PAY_SIGNATURE_EXPIRATION_IN_MS);
    }

    private static ApplePayPaymentHeader CreateApplePayPaymentHeader(Map paymentToken) {
        Map header = (Map) paymentToken.get(HEADER);
        ApplePayPaymentHeader applePayPaymentHeader = new ApplePayPaymentHeader();
        if (header.containsKey(APPLICATION_DATA)) {
            applePayPaymentHeader.setApplicationData(header.get(APPLICATION_DATA1).toString());

        }
        applePayPaymentHeader.setEphemeralPublicKey(header.get(EPHEMERAL_PUBLIC_KEY).toString());
        applePayPaymentHeader.setPublicKeyHash(header.get(PUBLIC_KEY_HASH).toString());
        applePayPaymentHeader.setTransactionId(header.get(TRANSACTION_ID).toString());
        return applePayPaymentHeader;
    }
}
