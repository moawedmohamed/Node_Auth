import QRCode from "qrcode";

const otpAuthUrl = process.argv[2];

if (!otpAuthUrl) {
    throw new Error("Pass otpAuthUrl as argument");
}

const main = async () => {
    await QRCode.toFile('totp.png', otpAuthUrl);
    console.log('saved QrCode');
}
main().catch(err => {
    console.log('error from QrCode file', err)
    process.exit(1);
})