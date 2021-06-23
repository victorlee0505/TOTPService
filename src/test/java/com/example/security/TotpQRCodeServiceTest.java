package com.example.security;

import org.junit.jupiter.api.Test;

public class TotpQRCodeServiceTest {
    @Test
    public void genQRCodeTest() {
        String barcodeText = "testing";
        try {
            TotpQRCodeService qrService = new TotpQRCodeService();

            qrService.generateGenericQRCodeImageToFile(barcodeText, "./src/main/resources/qrImage", "image.png");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
