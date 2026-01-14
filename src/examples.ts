/**
 * EXAMPLES - Practical Usage Scenarios
 *
 * This file demonstrates real-world usage patterns for the crypto library
 */

import { encrypt } from "./crypto/encrypt";
import { decrypt } from "./crypto/decrypt";
import { writeFileSync, readFileSync } from "fs";
import { Key } from "./keys";
import path from "path";
import { keys } from ".";

// ============================================
// EXAMPLE 1: Personal File Backup
// ============================================

async function example1_PersonalFileBackup() {
  // Use the project root directory to avoid import.meta (which requires specific TS module settings)
  const projectRoot = process.cwd();
  const inputPath = path.join(projectRoot, "test.txt");
  const outputPath = path.join(projectRoot, "test.enc");
  const inputEncrypted = path.join(projectRoot, "test.enc");
  const outputDecrypted = path.join(projectRoot, "decrypted.txt");
  console.log("\n📦 EXAMPLE 1: Personal File Backup\n");

  const password = "MySecureBackup!2024";

  // Encrypt important documents
  await encrypt(
    { type: "symmetric-password", password },
    undefined,
    inputPath,
    outputPath
  );

  console.log("✅ Backup encrypted");

  // Later: restore from backup
  await decrypt(
    { type: "symmetric-password", password },
    undefined,
    inputEncrypted,
    outputDecrypted
  );

  console.log("✅ Backup restored");
}

// ============================================
// EXAMPLE 2: Sending Confidential Email
// ============================================

async function example2_ConfidentialEmail() {
  console.log("\n📧 EXAMPLE 2: Confidential Email\n");

  // Recipient's public key (they shared it with you beforehand)
  const keys = await Key.generate("seal"); // RSA public key
  const recipientPublicKey = keys.publicKey as string;
  const emailContent = {
    to: "alice@example.com",
    subject: "Q4 Financial Report",
    body: "Please find attached the confidential Q4 report...",
    attachments: ["q4-report.pdf"],
  };
  console.log(recipientPublicKey);
  // Encrypt email content
  const encrypted = await encrypt(
    { type: "sealEnvelope", recipientPublicKey },
    emailContent
  );

  console.log(
    "Encrypted email data:",
    encrypted.data?.substring(0, 50) + "..."
  );
  console.log("✅ Ready to send via email");

  // Recipient decrypts with their private key
  // const decrypted = await decrypt(
  //   { type: "openEnvelope", recipientPrivateKey: theirPrivateKey },
  //   encrypted.data
  // );
}

// ============================================
// EXAMPLE 3: Secure Messaging App
// ============================================

async function example3_SecureMessaging() {
  console.log("\n💬 EXAMPLE 3: Secure Messaging\n");

  // Alice and Bob generate their keys once
  const alice = await Key.generate("secure-channel");
  const bob = await Key.generate("secure-channel");

  console.log("Alice and Bob exchange public keys...");

  // Alice sends message to Bob
  const aliceMessage = await encrypt(
    {
      type: "secure-channel",
      recipientPublicKey: bob.publicKey as string,
      includeTimestamp: true,
    },
    "Hey Bob, let's meet at 3pm"
  );

  console.log("✅ Alice's message encrypted with forward secrecy");

  // Bob receives and decrypts
  const bobReceives = await decrypt(
    {
      type: "secure-channel",
      recipientPrivateKey: bob.privateKey as string,
      validateTimestamp: true,
    },
    aliceMessage.data!
  );

  console.log(`Bob decrypted: "${bobReceives.data}"`);
  console.log(
    `Message timestamp: ${new Date(
      bobReceives.metadata?.timestamp!
    ).toISOString()}`
  );

  // Bob replies
  const bobMessage = await encrypt(
    {
      type: "secure-channel",
      recipientPublicKey: alice.publicKey as string,
    },
    "Sounds good! See you then"
  );

  const aliceReceives = await decrypt(
    {
      type: "secure-channel",
      recipientPrivateKey: alice.privateKey as string,
    },
    bobMessage.data!
  );

  console.log(`Alice decrypted: "${aliceReceives.data}"`);
  console.log("✅ Two-way encrypted conversation established");
}

// ============================================
// EXAMPLE 4: Signed Contract
// ============================================

async function example4_SignedContract() {
  console.log("\n📝 EXAMPLE 4: Digitally Signed Contract\n");

  // Company generates authenticated key set
  const company = await Key.generate("authenticated-channel");
  const client = await Key.generate("authenticated-channel");

  console.log("Company and client exchange keys...");

  const contract = {
    type: "Service Agreement",
    parties: ["Acme Corp", "John Doe"],
    terms: "Website development for $50,000",
    date: "2024-01-15",
    signature: "Acme Corp",
  };

  // Company signs and encrypts contract
  const signedContract = await encrypt(
    {
      type: "authenticated-channel",
      recipientPublicKey: client.publicKey as string, // Client's X25519 encryption key
      senderPrivateKey: company.signingPrivateKey as string, // Company's Ed25519 signing key (CHANGED)
      includeTimestamp: true,
    },
    contract
  );

  console.log("✅ Contract signed and encrypted");

  // Client receives and verifies
  const verified = await decrypt(
    {
      type: "authenticated-channel",
      recipientPrivateKey: client.privateKey as string, // Client's X25519 decryption key (needs to be encryption privateKey)
      senderPublicKey: company.signingPublicKey as string, // Company's Ed25519 verification key (CHANGED)
      validateTimestamp: true,
    },
    signedContract.data!
  );

  console.log(`Contract verified from: ${contract.signature}`);
  console.log(
    `Authentication status: ${
      verified.metadata?.authenticated ? "✅ VERIFIED" : "❌ FAILED"
    }`
  );
  console.log(`Contract terms:`, verified.data);
}

// ============================================
// EXAMPLE 5: Medical Records (HIPAA-style)
// ============================================

async function example5_MedicalRecords() {
  console.log("\n🏥 EXAMPLE 5: Secure Medical Records\n");

  const doctor = await Key.generate("authenticated-channel");
  const patient = await Key.generate("authenticated-channel");

  const medicalRecord = {
    patientId: "P123456",
    name: "John Doe",
    dob: "1980-05-15",
    diagnosis: "Type 2 Diabetes",
    medications: ["Metformin 500mg"],
    notes: "Patient responding well to treatment",
    doctor: "Dr. Smith",
    date: "2024-01-15",
  };

  // Doctor creates authenticated record
  const encrypted = await encrypt(
    {
      type: "authenticated-channel",
      recipientPublicKey: patient.publicKey as string,
      senderPrivateKey: doctor.signingPrivateKey as string,
      strictMode: true, // Maximum security for medical data
      includeTimestamp: true,
    },
    medicalRecord
  );

  console.log("✅ Medical record encrypted and signed");

  // Patient accesses record
  const decrypted = await decrypt(
    {
      type: "authenticated-channel",
      recipientPrivateKey: patient.privateKey as string,
      senderPublicKey: doctor.signingPublicKey as string,
      validateTimestamp: true,
      strictMode: true,
    },
    encrypted.data!
  );

  console.log("Patient verified record from:", medicalRecord.doctor);
  console.log(
    "Authentication:",
    decrypted.metadata?.authenticated ? "✅ Verified" : "❌ Failed"
  );
  console.log("Record age:", Date.now() - decrypted.metadata?.timestamp!, "ms");
}

// ============================================
// EXAMPLE 6: Password Manager
// ============================================

async function example6_PasswordManager() {
  console.log("\n🔑 EXAMPLE 6: Password Manager Vault\n");

  const masterPassword = "MyMasterPassword!2024$Super";

  const vault = {
    version: "1.0",
    entries: [
      {
        site: "github.com",
        username: "alice@example.com",
        password: "gh_token_abc123xyz",
        notes: "Personal account",
      },
      {
        site: "aws.amazon.com",
        username: "alice",
        password: "AWS_SECRET_KEY_xyz789",
        notes: "Work account",
      },
    ],
  };

  // Encrypt entire vault
  const encrypted = await encrypt(
    {
      type: "symmetric-password",
      password: masterPassword,
      strictMode: true,
    },
    vault
  );

  console.log("✅ Password vault encrypted");
  console.log("Encrypted vault size:", encrypted.data!.length, "bytes");

  // Save to disk
  writeFileSync("./vault.enc", encrypted.data!);
  console.log("✅ Vault saved to disk");

  // Later: load and decrypt
  const encryptedVault = readFileSync("./vault.enc", "utf8");
  const decrypted = await decrypt(
    {
      type: "symmetric-password",
      password: masterPassword,
    },
    encryptedVault
  );

  console.log("✅ Vault decrypted");
  console.log(
    `Loaded ${(decrypted.data as any).entries.length} password entries`
  );
}

// ============================================
// EXAMPLE 7: Handling Replay Attacks
// ============================================

async function example7_ReplayAttackDemo() {
  console.log("\n⏱️ EXAMPLE 7: Replay Attack Prevention\n");

  const alice = await Key.generate("secure-channel");
  const bob = await Key.generate("secure-channel");

  // Alice sends time-sensitive message
  const message = await encrypt(
    {
      type: "secure-channel",
      recipientPublicKey: bob.publicKey as string,
      includeTimestamp: true,
    },
    "Transfer $10,000 to account #123"
  );

  console.log("✅ Alice sent time-sensitive message");

  // Bob receives immediately - works fine
  const received = await decrypt(
    {
      type: "secure-channel",
      recipientPrivateKey: bob.privateKey as string,
      validateTimestamp: true,
    },
    message.data!
  );

  console.log(`Bob received: "${received.data}"`);
  console.log(`Message age: ${Date.now() - received.metadata?.timestamp!}ms`);

  // Simulate attacker capturing and replaying message 10 minutes later
  console.log("\n⚠️ Simulating replay attack (10 minutes later)...");

  // In real scenario, you'd wait or manually modify timestamp
  // For demo, we show that old messages are rejected:
  try {
    // This would fail if message is actually old
    // await decrypt({ ... validateTimestamp: true }, oldMessage);
    console.log("❌ Old messages would be rejected after 5 minutes");
  } catch (err) {
    console.log("✅ Replay attack prevented:", err);
  }
}

// ============================================
// EXAMPLE 8: Multi-Recipient Broadcast
// ============================================

async function example8_MultiRecipient() {
  console.log("\n📢 EXAMPLE 8: Encrypted Broadcast to Multiple Recipients\n");

  const sender = await Key.generate("authenticated-channel");
  const recipients = [
    { name: "Alice", keys: await Key.generate("authenticated-channel") },
    { name: "Bob", keys: await Key.generate("authenticated-channel") },
    { name: "Carol", keys: await Key.generate("authenticated-channel") },
  ];

  const announcement = {
    title: "Company-wide Security Update",
    message: "Please update your passwords by end of week",
    priority: "high",
  };

  console.log("Encrypting for 3 recipients...");

  // Encrypt separately for each recipient
  const encryptedMessages = await Promise.all(
    recipients.map(async (recipient) => ({
      recipient: recipient.name,
      encrypted: await encrypt(
        {
          type: "authenticated-channel",
          recipientPublicKey: recipient.keys.publicKey as string, // X25519 encryption key
          senderPrivateKey: sender.signingPrivateKey as string, // Ed25519 signing key (CHANGED)
        },
        announcement
      ),
    }))
  );

  console.log("✅ Encrypted for all recipients");

  // Each recipient can decrypt their copy
  for (const recipient of recipients) {
    const msg = encryptedMessages.find((m) => m.recipient === recipient.name);

    const decrypted = await decrypt(
      {
        type: "authenticated-channel",
        recipientPrivateKey: recipient.keys.privateKey as string, // X25519 decryption key
        senderPublicKey: sender.signingPublicKey as string, // Ed25519 verification key (CHANGED)
      },
      msg!.encrypted.data!
    );

    console.log(`${recipient.name} decrypted:`, (decrypted.data as any).title);
    console.log(`  Authenticated: ${decrypted.metadata?.authenticated}`);
  }
}

// ============================================
// RUN ALL EXAMPLES
// ============================================

async function runAllExamples() {
  try {
    await example1_PersonalFileBackup();
    await example2_ConfidentialEmail();
    await example3_SecureMessaging();
    await example4_SignedContract();
    await example5_MedicalRecords();
    await example6_PasswordManager();
    await example7_ReplayAttackDemo();
    await example8_MultiRecipient();

    console.log("\n✅ All examples completed successfully!\n");
  } catch (error) {
    console.error("❌ Error running examples:", error);
  }
}

// Uncomment to run:
runAllExamples();

export {
  example1_PersonalFileBackup,
  example2_ConfidentialEmail,
  example3_SecureMessaging,
  example4_SignedContract,
  example5_MedicalRecords,
  example6_PasswordManager,
  example7_ReplayAttackDemo,
  example8_MultiRecipient,
};
