// server/index.ts
import express2 from "express";
import multer2 from "multer";

// server/routes.ts
import { createServer } from "http";
import multer from "multer";

// server/storage.ts
var MemStorage = class {
  users;
  scanHistory;
  currentUserId;
  currentScanId;
  constructor() {
    this.users = /* @__PURE__ */ new Map();
    this.scanHistory = /* @__PURE__ */ new Map();
    this.currentUserId = 1;
    this.currentScanId = 1;
  }
  async getUser(id) {
    return this.users.get(id);
  }
  async getUserByUsername(username) {
    return Array.from(this.users.values()).find(
      (user) => user.username === username
    );
  }
  async createUser(insertUser) {
    const id = this.currentUserId++;
    const user = { ...insertUser, id };
    this.users.set(id, user);
    return user;
  }
  async addScanHistory(insertScan) {
    const id = this.currentScanId++;
    const scan = {
      id,
      scanType: insertScan.scanType,
      targetInput: insertScan.targetInput,
      result: insertScan.result,
      detectionCount: insertScan.detectionCount || 0,
      totalEngines: insertScan.totalEngines || 0,
      timestamp: /* @__PURE__ */ new Date()
    };
    this.scanHistory.set(id, scan);
    return scan;
  }
  async getScanHistory() {
    return Array.from(this.scanHistory.values()).sort(
      (a, b) => b.timestamp.getTime() - a.timestamp.getTime()
    );
  }
  async getAnalytics() {
    const scans = Array.from(this.scanHistory.values());
    const totalScans = scans.length;
    const threatsFound = scans.filter((s) => s.result === "malicious" || s.result === "suspicious").length;
    const filesSecure = scans.filter((s) => s.result === "clean").length;
    const scansByType = scans.reduce((acc, scan) => {
      acc[scan.scanType] = (acc[scan.scanType] || 0) + 1;
      return acc;
    }, {});
    const recentScans = scans.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime()).slice(0, 10);
    return {
      totalScans,
      threatsFound,
      filesSecure,
      scansByType,
      recentScans
    };
  }
};
var storage = new MemStorage();

// server/routes.ts
var VIRUS_TOTAL_API_KEY = "78d85eb7724a1cc398bd6c675070d0f8b9292bb84513efe65d08fa31accdfbf1";
var VIRUS_TOTAL_BASE = "https://www.virustotal.com/api/v3";
async function registerRoutes(app2) {
  const upload2 = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 650 * 1024 * 1024 }
    // 650MB limit
  });
  app2.post("/api/scan/url", async (req, res) => {
    try {
      const { url } = req.body;
      if (!url) {
        return res.status(400).json({ error: "URL is required" });
      }
      const formData = new FormData();
      formData.append("url", url);
      const response = await fetch(`${VIRUS_TOTAL_BASE}/urls`, {
        method: "POST",
        headers: {
          "x-apikey": VIRUS_TOTAL_API_KEY
        },
        body: formData
      });
      if (!response.ok) {
        throw new Error(`VirusTotal API error: ${response.statusText}`);
      }
      const data = await response.json();
      res.json(data);
    } catch (error) {
      console.error("URL scan error:", error);
      res.status(500).json({ error: "Failed to submit URL for scanning" });
    }
  });
  app2.post("/api/scan/file", upload2.single("file"), async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: "File is required" });
      }
      const formData = new FormData();
      formData.append("file", new Blob([req.file.buffer]), req.file.originalname);
      const response = await fetch(`${VIRUS_TOTAL_BASE}/files`, {
        method: "POST",
        headers: {
          "x-apikey": VIRUS_TOTAL_API_KEY
        },
        body: formData
      });
      if (!response.ok) {
        throw new Error(`VirusTotal API error: ${response.statusText}`);
      }
      const data = await response.json();
      res.json(data);
    } catch (error) {
      console.error("File scan error:", error);
      res.status(500).json({ error: "Failed to submit file for scanning" });
    }
  });
  app2.post("/api/analysis/url", async (req, res) => {
    try {
      const { url } = req.body;
      if (!url) {
        return res.status(400).json({ error: "URL is required" });
      }
      const encodedUrl = Buffer.from(url).toString("base64").replace(/=/g, "");
      const response = await fetch(`${VIRUS_TOTAL_BASE}/urls/${encodedUrl}`, {
        headers: {
          "x-apikey": VIRUS_TOTAL_API_KEY
        }
      });
      if (response.status === 404) {
        return res.status(404).json({
          error: "URL not found",
          message: "This URL has not been analyzed by VirusTotal yet. Try submitting it for scanning first."
        });
      }
      if (!response.ok) {
        throw new Error(`VirusTotal API error: ${response.statusText}`);
      }
      const data = await response.json();
      res.json(data);
    } catch (error) {
      console.error("URL analysis error:", error);
      res.status(500).json({ error: "Failed to get URL analysis" });
    }
  });
  app2.post("/api/analysis/file", async (req, res) => {
    try {
      const { id } = req.body;
      if (!id) {
        return res.status(400).json({ error: "File ID is required" });
      }
      console.log(`Getting file analysis for ID: ${id}`);
      let retries = 0;
      const maxRetries = 20;
      const retryDelay = 2e3;
      while (retries < maxRetries) {
        try {
          const analysisResponse = await fetch(`${VIRUS_TOTAL_BASE}/analyses/${id}`, {
            headers: {
              "x-apikey": VIRUS_TOTAL_API_KEY
            }
          });
          if (analysisResponse.ok) {
            const analysisData = await analysisResponse.json();
            console.log(`Analysis status: ${analysisData.data.attributes.status}, retry: ${retries}`);
            if (analysisData.data.attributes.status === "completed") {
              const fileId = analysisData.data.attributes.file_info?.sha256 || analysisData.data.attributes.file_info?.md5 || analysisData.data.attributes.file_info?.sha1;
              if (fileId) {
                console.log(`Getting file details for hash: ${fileId}`);
                const fileResponse = await fetch(`${VIRUS_TOTAL_BASE}/files/${fileId}`, {
                  headers: {
                    "x-apikey": VIRUS_TOTAL_API_KEY
                  }
                });
                if (fileResponse.ok) {
                  const fileData = await fileResponse.json();
                  console.log("File analysis completed successfully");
                  return res.json(fileData);
                } else {
                  console.log(`File response not ok: ${fileResponse.status}`);
                }
              }
              console.log("Returning analysis data directly");
              return res.json(analysisData);
            }
          } else if (analysisResponse.status === 404) {
            console.log(`Analysis not found (404), retry ${retries}/${maxRetries}`);
          } else {
            console.log(`Analysis response error: ${analysisResponse.status}`);
          }
        } catch (fetchError) {
          console.error(`Fetch error on retry ${retries}:`, fetchError);
        }
        retries++;
        if (retries < maxRetries) {
          console.log(`Waiting ${retryDelay}ms before retry ${retries}/${maxRetries}`);
          await new Promise((resolve) => setTimeout(resolve, retryDelay));
        }
      }
      console.log("Analysis timed out after all retries");
      res.status(408).json({
        error: "Analysis timeout",
        message: "File analysis is taking longer than expected. The file may be large or complex."
      });
    } catch (error) {
      console.error("File analysis error:", error);
      res.status(500).json({ error: "Failed to get file analysis" });
    }
  });
  app2.post("/api/analysis/ip", async (req, res) => {
    try {
      const { ip } = req.body;
      if (!ip) {
        return res.status(400).json({ error: "IP address is required" });
      }
      const response = await fetch(`${VIRUS_TOTAL_BASE}/ip_addresses/${ip}`, {
        headers: {
          "x-apikey": VIRUS_TOTAL_API_KEY
        }
      });
      if (!response.ok) {
        throw new Error(`VirusTotal API error: ${response.statusText}`);
      }
      const data = await response.json();
      res.json(data);
    } catch (error) {
      console.error("IP analysis error:", error);
      res.status(500).json({ error: "Failed to get IP analysis" });
    }
  });
  app2.post("/api/analysis/domain", async (req, res) => {
    try {
      const { domain } = req.body;
      if (!domain) {
        return res.status(400).json({ error: "Domain is required" });
      }
      const response = await fetch(`${VIRUS_TOTAL_BASE}/domains/${domain}`, {
        headers: {
          "x-apikey": VIRUS_TOTAL_API_KEY
        }
      });
      if (!response.ok) {
        throw new Error(`VirusTotal API error: ${response.statusText}`);
      }
      const data = await response.json();
      res.json(data);
    } catch (error) {
      console.error("Domain analysis error:", error);
      res.status(500).json({ error: "Failed to get domain analysis" });
    }
  });
  app2.post("/api/analysis/hash", async (req, res) => {
    try {
      const { hash } = req.body;
      if (!hash) {
        return res.status(400).json({ error: "Hash is required" });
      }
      const response = await fetch(`${VIRUS_TOTAL_BASE}/files/${hash}`, {
        headers: {
          "x-apikey": VIRUS_TOTAL_API_KEY
        }
      });
      if (!response.ok) {
        throw new Error(`VirusTotal API error: ${response.statusText}`);
      }
      const data = await response.json();
      res.json(data);
    } catch (error) {
      console.error("Hash analysis error:", error);
      res.status(500).json({ error: "Failed to get hash analysis" });
    }
  });
  app2.post("/api/scan/history", async (req, res) => {
    try {
      const scanData = req.body;
      const scan = await storage.addScanHistory(scanData);
      res.json(scan);
    } catch (error) {
      console.error("Add scan history error:", error);
      res.status(500).json({ error: "Failed to save scan history" });
    }
  });
  app2.get("/api/analytics", async (req, res) => {
    try {
      const analytics = await storage.getAnalytics();
      res.json(analytics);
    } catch (error) {
      console.error("Analytics error:", error);
      res.status(500).json({ error: "Failed to get analytics" });
    }
  });
  app2.get("/api/scan/history", async (req, res) => {
    try {
      const history = await storage.getScanHistory();
      res.json(history);
    } catch (error) {
      console.error("Get scan history error:", error);
      res.status(500).json({ error: "Failed to get scan history" });
    }
  });
  app2.get("/api/virustotal/status", async (req, res) => {
    try {
      const response = await fetch(`${VIRUS_TOTAL_BASE}/metadata`, {
        headers: {
          "x-apikey": VIRUS_TOTAL_API_KEY
        }
      });
      if (!response.ok) {
        throw new Error(`VirusTotal API error: ${response.statusText}`);
      }
      const data = await response.json();
      const engines = data.data?.attributes?.engines || {};
      const engineCount = Object.keys(engines).length;
      const activeEngines = Object.values(engines).filter((engine) => engine.update).length;
      res.json({
        totalEngines: engineCount,
        activeEngines,
        lastUpdate: (/* @__PURE__ */ new Date()).toISOString(),
        engines,
        apiStatus: "operational"
      });
    } catch (error) {
      console.error("VirusTotal status error:", error);
      res.json({
        totalEngines: 70,
        activeEngines: 68,
        lastUpdate: (/* @__PURE__ */ new Date()).toISOString(),
        engines: {},
        apiStatus: "limited"
      });
    }
  });
  const httpServer = createServer(app2);
  return httpServer;
}

// server/vite.ts
import express from "express";
import fs from "fs";
import path2 from "path";
import { createServer as createViteServer, createLogger } from "vite";

// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";
import runtimeErrorOverlay from "@replit/vite-plugin-runtime-error-modal";
var vite_config_default = defineConfig({
  plugins: [
    react(),
    runtimeErrorOverlay(),
    ...process.env.NODE_ENV !== "production" && process.env.REPL_ID !== void 0 ? [
      await import("@replit/vite-plugin-cartographer").then(
        (m) => m.cartographer()
      )
    ] : []
  ],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "client", "src"),
      "@shared": path.resolve(import.meta.dirname, "shared"),
      "@assets": path.resolve(import.meta.dirname, "attached_assets")
    }
  },
  root: path.resolve(import.meta.dirname, "client"),
  build: {
    outDir: path.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true
  }
});

// server/vite.ts
import { nanoid } from "nanoid";
var viteLogger = createLogger();
function log(message, source = "express") {
  const formattedTime = (/* @__PURE__ */ new Date()).toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true
  });
  console.log(`${formattedTime} [${source}] ${message}`);
}
async function setupVite(app2, server) {
  const serverOptions = {
    middlewareMode: true,
    hmr: { server },
    allowedHosts: true
  };
  const vite = await createViteServer({
    ...vite_config_default,
    configFile: false,
    customLogger: {
      ...viteLogger,
      error: (msg, options) => {
        viteLogger.error(msg, options);
        process.exit(1);
      }
    },
    server: serverOptions,
    appType: "custom"
  });
  app2.use(vite.middlewares);
  app2.use("*", async (req, res, next) => {
    const url = req.originalUrl;
    try {
      const clientTemplate = path2.resolve(
        import.meta.dirname,
        "..",
        "client",
        "index.html"
      );
      let template = await fs.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid()}"`
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
}
function serveStatic(app2) {
  const distPath = path2.resolve(import.meta.dirname, "public");
  if (!fs.existsSync(distPath)) {
    throw new Error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app2.use(express.static(distPath));
  app2.use("*", (_req, res) => {
    res.sendFile(path2.resolve(distPath, "index.html"));
  });
}

// server/index.ts
var app = express2();
app.use(express2.json());
app.use(express2.urlencoded({ extended: false }));
var upload = multer2({
  storage: multer2.memoryStorage(),
  limits: { fileSize: 650 * 1024 * 1024 }
  // 650MB limit
});
app.locals.upload = upload;
app.use((req, res, next) => {
  const start = Date.now();
  const path3 = req.path;
  let capturedJsonResponse = void 0;
  const originalResJson = res.json;
  res.json = function(bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };
  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path3.startsWith("/api")) {
      let logLine = `${req.method} ${path3} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }
      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "\u2026";
      }
      log(logLine);
    }
  });
  next();
});
(async () => {
  const server = await registerRoutes(app);
  app.use((err, _req, res, _next) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";
    res.status(status).json({ message });
    throw err;
  });
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }
  const port = 5e3;
  server.listen({
    port,
    host: "0.0.0.0",
    reusePort: true
  }, () => {
    log(`serving on port ${port}`);
  });
})();
