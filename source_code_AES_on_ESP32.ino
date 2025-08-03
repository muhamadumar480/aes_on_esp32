#include <WiFi.h>
#include "mbedtls/aes.h"

#define BUFFER_SIZE 16  // AES block size (16 bytes)
#define MAX_INPUT 64    // Maximum input length

// Timing measurement structure
struct TimingData {
  unsigned long key_setup;
  unsigned long encryption;
  unsigned long decryption;
};

// Global variables
mbedtls_aes_context aes;
unsigned char key[16] = {
  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

void printHex(const char* label, const unsigned char* data, size_t len) {
  Serial.print(label);
  for (size_t i = 0; i < len; i++) {
    Serial.printf("%02x ", data[i]);
  }
  Serial.println();
}

void printTiming(const char* label, unsigned long time) {
  Serial.print(label);
  Serial.print(time);
  Serial.println(" μs");
}

TimingData processBlock(const unsigned char* input, unsigned char* output) {
  TimingData timing;
  unsigned char ciphertext[BUFFER_SIZE];
  unsigned char decrypted[BUFFER_SIZE];

  // Initialize AES
  mbedtls_aes_init(&aes);

  // Key setup timing
  unsigned long start = micros();
  mbedtls_aes_setkey_enc(&aes, key, 128);
  timing.key_setup = micros() - start;

  // Encryption timing
  start = micros();
  mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, input, ciphertext);
  timing.encryption = micros() - start;

  // Decryption timing
  start = micros();
  mbedtls_aes_setkey_dec(&aes, key, 128);
  mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, ciphertext, decrypted);
  timing.decryption = micros() - start;

  // Copy result if needed
  if (output != NULL) {
    memcpy(output, ciphertext, BUFFER_SIZE);
  }

  // Cleanup
  mbedtls_aes_free(&aes);
  return timing;
}

void setup() {
  Serial.begin(115200);
  while (!Serial); // Wait for serial connection
  
  WiFi.mode(WIFI_OFF); // Reduce interference
  
  Serial.println("\nAES-128 ECB Character-by-Character Timing Analyzer");
  Serial.println("================================================");
  Serial.println("Enter text to analyze (max 64 characters):");
}

void loop() {
  if (Serial.available()) {
    // Read input string
    String input = Serial.readStringUntil('\n');
    input.trim();
    
    if (input.length() == 0) return;
    
    Serial.println("\n=== Analysis Results ===");
    Serial.print("Input Text: \"");
    Serial.print(input);
    Serial.println("\"");
    
    // Process each character individually
    for (int i = 0; i < input.length(); i++) {
      // Prepare block (current character + padding)
      unsigned char block[BUFFER_SIZE] = {0};
      block[0] = input[i];
      
      Serial.printf("\nCharacter %d: '%c' (0x%02x)\n", i+1, input[i], input[i]);
      
      // Process the block
      unsigned char ciphertext[BUFFER_SIZE];
      TimingData timing = processBlock(block, ciphertext);
      
      // Display results
      printHex("Block:      ", block, BUFFER_SIZE);
      printHex("Ciphertext: ", ciphertext, BUFFER_SIZE);
      printTiming("Key Setup:  ", timing.key_setup);
      printTiming("Encryption: ", timing.encryption);
      printTiming("Decryption: ", timing.decryption);
      
      Serial.println("----------------------");
    }
    
    Serial.println("\nAnalysis complete. Enter new text to analyze.");
  }
}