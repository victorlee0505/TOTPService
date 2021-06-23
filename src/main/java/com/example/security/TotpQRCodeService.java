package com.example.security;

import java.awt.image.BufferedImage;
import java.nio.file.Path;
import java.nio.file.Paths;

import com.example.security.constants.TotpConstant;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

/**
 * from https://www.baeldung.com/java-generating-barcodes-qr-codes
 */
public class TotpQRCodeService {
    
    /**
     * Save a QRCode into a file
     * 
     * @param cred
     * @param path
     * @param imageName
     * @throws Exception
     */
    public void generateQRCodeImageToFile(TotpCredential cred, String path, String imageName) throws Exception {

        Path dir = Paths.get(path);
        if (!dir.toFile().exists()) {
            dir.toFile().mkdirs();
        }
        Path file = dir.resolve(imageName);

        String barcodeText = String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s", cred.getProvider(),
                cred.getUserId(), cred.getSecret(), cred.getProvider());
        MatrixToImageWriter.writeToPath(getQRCode(barcodeText), TotpConstant.PNG, file);
    }

    /**
     * return a QRCode as java.awt.image.BufferedImage
     * 
     * @param cred
     * @return
     * @throws Exception
     */
    public BufferedImage generateQRCodeBufferedImage(TotpCredential cred) throws Exception {

        String barcodeText = String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s", cred.getProvider(),
                cred.getUserId(), cred.getSecret(), cred.getProvider());
        return MatrixToImageWriter.toBufferedImage(getQRCode(barcodeText));
    }

    private BitMatrix getQRCode(String barcodeText) throws Exception {
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix = qrCodeWriter.encode(barcodeText, BarcodeFormat.QR_CODE, 200, 200);

        return bitMatrix;
    }

    /**
     * Generic QRCode generator to File
     * 
     * @param barcodeText
     * @param path
     * @param imageName
     * @throws Exception
     */
    public void generateGenericQRCodeImageToFile(String barcodeText, String path, String imageName) throws Exception {

        Path dir = Paths.get(path);
        if (!dir.toFile().exists()) {
            dir.toFile().mkdirs();
        }
        Path file = dir.resolve(imageName);

        MatrixToImageWriter.writeToPath(getQRCode(barcodeText), TotpConstant.PNG, file);
    }

    /**
     * Generic QRCode generator to java.awt.image.BufferedImage
     * 
     * @param barcodeText
     * @param path
     * @param imageName
     * @throws Exception
     */
    public BufferedImage generateGenericQRCodeBufferedImage(String barcodeText) throws Exception {

        return MatrixToImageWriter.toBufferedImage(getQRCode(barcodeText));
    }
}
