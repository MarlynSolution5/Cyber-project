import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI } from "@google/genai";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = 3000;

// Initialize the Gemini AI client
const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
  httpOptions: {
    headers: {
      'User-Agent': 'aistudio-build',
    }
  }
});

app.use(express.json());

// API route first: Code analysis, decompilation & vulnerability audit
app.post("/api/analyze-code", async (req, res) => {
  try {
    const { code, filename, customPrompt } = req.body;

    if (!code) {
      return res.status(400).json({ error: "No code or assembly snippet was provided for analysis." });
    }

    const systemInstruction = `
      You are an expert reverse engineer, binary security analyst, and code quality supervisor.
      Your goal is to assist software developers and security researchers in decompiling compiled-style snippets, identifying vulnerability vectors (buffer overflows, off-by-one errors, unchecked input, hardcoded keys), and recommending secure refactoring layouts.
      
      Structure your response as a strict JSON document matching this schema:
      {
        "pseudocode": "Beautiful, highly readible, properly indented C-like pseudocode representing the compiled flow",
        "analysis": "A high-level explanation of what the logic does, its objective, and key subroutines",
        "technicalDebtScore": 85, // out of 100 assessing code quality and architectural issues
        "highRiskPaths": [
          {
            "riskType": "High | Medium | Low",
            "location": "e.g., inside validate_input offset 0x4001f0",
            "finding": "Descriptive security bug, vulnerability explanation, or excessive formatting depth",
            "resolution": "Specific instructions on how to secure or optimize this code path"
          }
        ],
        "remediationCode": "Refactored, clean, secure, and modern C or TypeScript code addressing the debt"
      }
    `;

    const userPrompt = `
      Analyze the following source block. If it is Assembly, decompile it to readable pseudocode. If it is high-level code, audit its security, identify high-risk code paths, and calculate its code health metrics.
      
      File reference: ${filename || "unidentified_segment.asm"}
      Additional Instruction: ${customPrompt || "Perform full security audit and compile pseudocode."}

      === INPUT CODE ===
      ${code}
      === END INPUT CODE ===
    `;

    // We use gemini-3.5-flash for binary analysis explanation & decompilation simulation
    const response = await ai.models.generateContent({
      model: "gemini-3.5-flash",
      contents: userPrompt,
      config: {
        systemInstruction: systemInstruction,
        responseMimeType: "application/json",
      },
    });

    const textOutput = response.text;
    if (!textOutput) {
      throw new Error("No response text received from the AI model.");
    }

    // Try to parse JSON output safely
    const result = JSON.parse(textOutput.trim());
    return res.json(result);

  } catch (error: any) {
    console.error("Analysis route error:", error);
    return res.status(500).json({
      error: "Analysis failed to execute",
      details: error.message || "Unknown error during AI model execution."
    });
  }
});

// Health check endpoint
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", time: new Date().toISOString() });
});

// Configure Vite middleware in development or static serving in production
async function configureServer() {
  if (process.env.NODE_ENV !== "production") {
    console.log("Configuring Vite middleware in dev mode...");
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    console.log("Serving static production assets...");
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Binary workspace active on port ${PORT}`);
  });
}

configureServer().catch((err) => {
  console.error("Failed to configure server:", err);
});
