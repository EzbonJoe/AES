// Import required modules
const crypto = require("crypto");
const readline = require("readline");

// Create readline interface for terminal input
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

// Function to derive a 256-bit AES key from user input
function deriveKey(secretKey) {
    return crypto.createHash("sha256").update(secretKey).digest();
}

// AES Encryption Function
function encryptAES(plaintext, secretKey) {
    const iv = crypto.randomBytes(16); // Generate random IV
    const key = deriveKey(secretKey);

    const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);

    let encrypted = cipher.update(plaintext, "utf8", "hex");
    encrypted += cipher.final("hex");

    return {
        iv: iv.toString("hex"),
        ciphertext: encrypted
    };
}

// AES Decryption Function
function decryptAES(ciphertext, secretKey, ivHex) {
    const iv = Buffer.from(ivHex, "hex");
    const key = deriveKey(secretKey);

    const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);

    let decrypted = decipher.update(ciphertext, "hex", "utf8");
    decrypted += decipher.final("utf8");

    return decrypted;
}

// User Input Flow 
rl.question("Enter plaintext message: ", (plaintext) => {
    rl.question("Enter secret key (min 128-bit recommended): ", (secretKey) => {

        // Encrypt the message
        const encryptedData = encryptAES(plaintext, secretKey);

        console.log("\n--- Encryption Output ---");
        console.log("Ciphertext:", encryptedData.ciphertext);
        console.log("IV:", encryptedData.iv);

        // Decrypt the message
        const decryptedText = decryptAES(
            encryptedData.ciphertext,
            secretKey,
            encryptedData.iv
        );

        console.log("\n--- Decryption Output ---");
        console.log("Decrypted Text:", decryptedText);

        rl.close();
    });
});
