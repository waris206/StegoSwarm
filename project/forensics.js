import fs from 'fs';

// Calculate the Shannon Entropy of a file (Mathematical randomness)
export function calculateShannonEntropy(filePath) {
  try {
    const buffer = fs.readFileSync(filePath);
    const frequencies = new Array(256).fill(0);
    
    // Count byte frequencies
    for (let i = 0; i < buffer.length; i++) {
      frequencies[buffer[i]]++;
    }
    
    let entropy = 0;
    // Apply the Shannon Entropy formula
    for (let i = 0; i < 256; i++) {
      if (frequencies[i] > 0) {
        const p = frequencies[i] / buffer.length;
        entropy -= p * Math.log2(p);
      }
    }
    return entropy.toFixed(4); // Returns a score between 0 and 8
  } catch (error) {
    console.error("Entropy calculation failed:", error);
    return "Error";
  }
}