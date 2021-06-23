# TOTP Service

TOTP Service is a JAVA library as solution to TOTP authentication. 

## Installation

This is a Maven Project on JDK11.

This is a Library and does not run standalone.

Please check this project for implementation

```bash
mvn install
```

For implementation, this check TOTPDemoApp which can be found in
[TOTPDemoApp](https://github.com/victorlee0505/TOTPDemoApp.git)

## Test
I have included a interactive test in TotpTest.java, run by main();

it will generate a QRCode as PNG under `src\main\resources\qrimage\testQR.png`

Use Microsoft / Google Authenticator app on your phone (iOS/Andriod) to scan QRCode.

Type in the passcode from the app to your cmd/terminal to verify.


## License
[MIT](https://choosealicense.com/licenses/mit/)