/**
 * Proxy mTLS para SEFAZ NFeDistribuicaoDFe
 */

const express = require("express");
const https = require("https");
const forge = require("node-forge");

const app = express();
app.use(express.json({ limit: "10mb" }));

const SEFAZ_HOST = "www1.nfe.fazenda.gov.br";
const SEFAZ_PATH = "/NFeDistribuicaoDFe/NFeDistribuicaoDFe.asmx";
const SOAP_ACTION = "http://www.portalfiscal.inf.br/nfe/wsdl/NFeDistribuicaoDFe/NfeDistDFeInteresse";
const PORT = process.env.PORT || 3000;
const PROXY_TOKEN = process.env.PROXY_TOKEN;

function authMiddleware(req, res, next) {
  const token = req.headers["x-proxy-token"];
  if (!PROXY_TOKEN || token !== PROXY_TOKEN) {
    return res.status(401).json({ error: "Token invalido" });
  }
  next();
}

function extractPfxCredentials(pfxBuffer, password) {
  const asn1 = forge.asn1.fromDer(pfxBuffer.toString("binary"));
  const p12 = forge.pkcs12.pkcs12FromAsn1(asn1, password, false);

  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
  const cert = certBags[forge.pki.oids.certBag]?.[0]?.cert;

  const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
  const privateKey = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag]?.[0]?.key;

  if (!cert || !privateKey) {
    throw new Error("Certificado ou chave privada nao encontrados no PFX.");
  }

  return {
    certPem: forge.pki.certificateToPem(cert),
    keyPem: forge.pki.privateKeyToPem(privateKey),
  };
}

function sendToSefaz(soapBody, certPem, keyPem) {
  return new Promise((resolve, reject) => {
    const bodyBytes = Buffer.from(soapBody, "utf-8");

    const agent = new https.Agent({
      cert: certPem,
      key: keyPem,
      rejectUnauthorized: true,
      minVersion: "TLSv1.2",
    });

    const req = https.request(
      {
        hostname: SEFAZ_HOST,
        port: 443,
        path: SEFAZ_PATH,
        method: "POST",
        agent,
        headers: {
          "Content-Type": 'application/soap+xml; charset=utf-8; action="' + SOAP_ACTION + '"',
          "Content-Length": bodyBytes.length,
          "User-Agent": "BuscaNotas/1.0",
          "Connection": "close",
        },
        timeout: 60000,
      },
      (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => {
          const fullResponse = Buffer.concat(chunks).toString("utf-8");
          // Check status code from the response object
          if (res.statusCode !== 200) {
            reject(new Error("SEFAZ HTTP " + res.statusCode + ": " + fullResponse.substring(0, 500)));
            return;
          }
          resolve(fullResponse);
        });
      }
    );

    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy(new Error("Timeout na conexao com a SEFAZ"));
    });
    req.write(bodyBytes);
    req.end();
  });
}

function makeJsonMtlsRequest(hostname, path, method, body, certPem, keyPem) {
  return new Promise((resolve, reject) => {
    const bodyStr = body ? JSON.stringify(body) : null;
    const bodyBytes = bodyStr ? Buffer.from(bodyStr, "utf-8") : null;

    const agent = new https.Agent({
      cert: certPem,
      key: keyPem,
      rejectUnauthorized: true,
      minVersion: "TLSv1.2",
    });

    const headers = {
      Accept: "application/json",
      "User-Agent": "BuscaNotas/1.0",
    };
    if (bodyBytes) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = bodyBytes.length;
    }

    const req = https.request(
      {
        hostname,
        port: 443,
        path,
        method: method.toUpperCase(),
        agent,
        headers,
        timeout: 60000,
      },
      (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => {
          const responseBody = Buffer.concat(chunks).toString("utf-8");
          resolve({ status: res.statusCode, body: responseBody });
        });
      }
    );

    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy(new Error("Timeout na conexao com ADN"));
    });
    if (bodyBytes) req.write(bodyBytes);
    req.end();
  });
}

app.post("/adn/request", authMiddleware, async (req, res) => {
  try {
    const { method, path, body, pfxUrl, password } = req.body;
    if (!method || !path || !pfxUrl || !password) {
      return res.status(400).json({ error: "method, path, pfxUrl e password sao obrigatorios" });
    }

    const pfxResponse = await fetch(pfxUrl);
    if (!pfxResponse.ok) {
      return res.status(502).json({ error: "Erro ao baixar certificado PFX" });
    }
    const pfxBuffer = Buffer.from(await pfxResponse.arrayBuffer());
    const { certPem, keyPem } = extractPfxCredentials(pfxBuffer, password);

    const result = await makeJsonMtlsRequest(
      "adn.nfse.gov.br",
      path,
      method.toUpperCase(),
      body || null,
      certPem,
      keyPem
    );

    res.json(result);
  } catch (error) {
    console.error("Erro no proxy ADN:", error.message);
    res.status(500).json({ error: error.message });
  }
});

app.post("/sefaz/distribuicao", authMiddleware, async (req, res) => {
  try {
    const { soapBody, pfxUrl, password } = req.body;
    if (!soapBody || !pfxUrl || !password) {
      return res.status(400).json({ error: "soapBody, pfxUrl e password sao obrigatorios" });
    }

    const pfxResponse = await fetch(pfxUrl);
    if (!pfxResponse.ok) {
      return res.status(502).json({ error: "Erro ao baixar certificado PFX" });
    }
    const pfxBuffer = Buffer.from(await pfxResponse.arrayBuffer());

    const { certPem, keyPem } = extractPfxCredentials(pfxBuffer, password);

    const responseXml = await sendToSefaz(soapBody, certPem, keyPem);

    res.json({ xml: responseXml });
  } catch (error) {
    console.error("Erro no proxy:", error.message);
    res.status(500).json({ error: error.message });
  }
});

app.get("/health", (req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log("Proxy SEFAZ rodando na porta " + PORT);
});
