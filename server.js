/**
 * Proxy mTLS para SEFAZ NFeDistribuicaoDFe
 *
 * Deploy: Railway, Render, Fly.io, ou qualquer VPS com Node.js 18+
 * Comandos:
 *   npm install express node-forge
 *   node server.js
 *
 * Variáveis de ambiente:
 *   PORT          - porta (default 3000)
 *   PROXY_TOKEN   - token de autenticação (obrigatório)
 */

const express = require("express");
const https = require("https");
const forge = require("node-forge");
const { SignedXml } = require("xml-crypto");

const app = express();
app.use(express.json({ limit: "10mb" }));

const SEFAZ_HOST = "www1.nfe.fazenda.gov.br";
const SEFAZ_PATH = "/NFeDistribuicaoDFe/NFeDistribuicaoDFe.asmx";
const SOAP_ACTION =
  "http://www.portalfiscal.inf.br/nfe/wsdl/NFeDistribuicaoDFe/NfeDistDFeInteresse";
const PORT = process.env.PORT || 3000;
const PROXY_TOKEN = process.env.PROXY_TOKEN;

function authMiddleware(req, res, next) {
  const token = req.headers["x-proxy-token"];
  if (!PROXY_TOKEN || token !== PROXY_TOKEN) {
    return res.status(401).json({ error: "Token inválido" });
  }
  next();
}

/**
 * Extrai certificado (PEM) e chave privada (PEM) de um buffer PFX.
 */
function extractPfxCredentials(pfxBuffer, password) {
  const asn1 = forge.asn1.fromDer(pfxBuffer.toString("binary"));
  const p12 = forge.pkcs12.pkcs12FromAsn1(asn1, password, false);

  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
  const cert = certBags[forge.pki.oids.certBag]?.[0]?.cert;

  const keyBags = p12.getBags({
    bagType: forge.pki.oids.pkcs8ShroudedKeyBag,
  });
  const privateKey = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag]?.[0]?.key;

  if (!cert || !privateKey) {
    throw new Error("Certificado ou chave privada não encontrados no PFX.");
  }

  return {
    certPem: forge.pki.certificateToPem(cert),
    keyPem: forge.pki.privateKeyToPem(privateKey),
  };
}

/**
 * Assina um XML de evento (manifestação) usando XMLDSig.
 */
function signEventXml(eventXml, certPem, keyPem) {
  const certBase64 = certPem
    .replace("-----BEGIN CERTIFICATE-----", "")
    .replace("-----END CERTIFICATE-----", "")
    .replace(/\s+/g, "");

  const sig = new SignedXml();
  sig.signingKey = keyPem;
  sig.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
  sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
  sig.keyInfoProvider = {
    getKeyInfo: function () {
      return '<X509Data><X509Certificate>' + certBase64 + '</X509Certificate></X509Data>';
    },
  };
  sig.addReference(
    "//*[local-name()='infEvento']",
    ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"],
    "http://www.w3.org/2000/09/xmldsig#sha1"
  );
  sig.computeSignature(eventXml, {
    prefix: "ds",
    location: { reference: "//*[local-name()='infEvento']", action: "after" },
  });
  return sig.getSignedXml();
}

/**
 * Faz a requisição SOAP à SEFAZ usando mTLS.
 */
function sendToSefaz(soapBody, certPem, keyPem, options = {}) {
  const host = options.host || SEFAZ_HOST;
  const path = options.path || SEFAZ_PATH;
  const action = options.action || SOAP_ACTION;
  const soapVersion = options.soapVersion || "1.2";
  return new Promise((resolve, reject) => {
    const bodyBytes = Buffer.from(soapBody, "utf-8");

    const agent = new https.Agent({
      cert: certPem,
      key: keyPem,
      rejectUnauthorized: true,
      minVersion: "TLSv1.2",
    });

    const headers = {
      "Content-Length": bodyBytes.length,
      "User-Agent": "BuscaNotas/1.0",
      "Connection": "close",
    };

    // SOAP 1.1: text/xml + SOAPAction header; SOAP 1.2: application/soap+xml + action in Content-Type
    if (soapVersion === "1.1") {
      headers["Content-Type"] = "text/xml; charset=utf-8";
      headers["SOAPAction"] = `"${action}"`;
    } else {
      headers["Content-Type"] = `application/soap+xml; charset=utf-8; action="${action}"`;
    }

    const req = https.request(
      {
        hostname: host,
        port: 443,
        path: path,
        method: "POST",
        agent,
        headers,
        timeout: 60000,
      },
      (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => {
          let body = Buffer.concat(chunks).toString("utf-8");

          if (res.headers["transfer-encoding"] && res.headers["transfer-encoding"].includes("chunked")) {
            body = decodeChunked(body);
          }

          if (res.statusCode !== 200) {
            reject(
              new Error(`SEFAZ HTTP ${res.statusCode}: ${body.substring(0, 1000)}`)
            );
            return;
          }
          resolve(body);
        });
      }
    );

    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy(new Error("Timeout na conexão com a SEFAZ"));
    });
    req.write(bodyBytes);
    req.end();
  });
}

function decodeChunked(body) {
  let result = "";
  let pos = 0;
  while (pos < body.length) {
    const lineEnd = body.indexOf("\r\n", pos);
    if (lineEnd === -1) break;
    const chunkSize = parseInt(body.substring(pos, lineEnd), 16);
    if (isNaN(chunkSize) || chunkSize === 0) break;
    pos = lineEnd + 2;
    result += body.substring(pos, pos + chunkSize);
    pos += chunkSize + 2;
  }
  return result;
}

/**
 * Faz uma requisição HTTPS JSON com mTLS (para ADN/NFS-e Nacional).
 */
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
      req.destroy(new Error("Timeout na conexão com ADN"));
    });
    if (bodyBytes) req.write(bodyBytes);
    req.end();
  });
}

app.post("/adn/request", authMiddleware, async (req, res) => {
  try {
    const { method, path, body, pfxUrl, password } = req.body;
    if (!method || !path || !pfxUrl || !password) {
      return res.status(400).json({ error: "method, path, pfxUrl e password são obrigatórios" });
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
      return res.status(400).json({
        error: "soapBody, pfxUrl e password são obrigatórios",
      });
    }

    // Baixa o PFX
    const pfxResponse = await fetch(pfxUrl);
    if (!pfxResponse.ok) {
      return res
        .status(502)
        .json({ error: "Erro ao baixar certificado PFX" });
    }
    const pfxBuffer = Buffer.from(await pfxResponse.arrayBuffer());

    // Extrai credenciais
    const { certPem, keyPem } = extractPfxCredentials(pfxBuffer, password);

    // Envia para SEFAZ
    const responseXml = await sendToSefaz(soapBody, certPem, keyPem);

    res.json({ xml: responseXml });
  } catch (error) {
    console.error("Erro no proxy:", error.message);
    res.status(500).json({ error: error.message });
  }
});

app.post("/sefaz/manifestacao", authMiddleware, async (req, res) => {
  try {
    const { eventXml, pfxUrl, password } = req.body;
    if (!eventXml || !pfxUrl || !password) {
      return res.status(400).json({ error: "eventXml, pfxUrl e password são obrigatórios" });
    }

    const pfxResponse = await fetch(pfxUrl);
    if (!pfxResponse.ok) {
      return res.status(502).json({ error: "Erro ao baixar certificado PFX" });
    }
    const pfxBuffer = Buffer.from(await pfxResponse.arrayBuffer());
    const { certPem, keyPem } = extractPfxCredentials(pfxBuffer, password);

    const signedXml = signEventXml(eventXml, certPem, keyPem);

    // Debug: se ?debug=true, retorna o XML assinado e o envelope completo sem enviar à SEFAZ
    if (req.body.debug === true || req.query.debug === "true") {
      const soapEnvelope =
        '<?xml version="1.0" encoding="UTF-8"?>' +
        '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">' +
        '<soap:Header>' +
        '<nfeCabecMsg xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4"><cUF>91</cUF><versaoDados>1.00</versaoDados></nfeCabecMsg>' +
        '</soap:Header>' +
        '<soap:Body>' +
        '<nfeRecepcaoEventoNF xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4">' +
        '<nfeDadosMsg>' + signedXml + '</nfeDadosMsg>' +
        '</nfeRecepcaoEventoNF>' +
        '</soap:Body>' +
        '</soap:Envelope>';
      return res.json({ signedXml: signedXml.substring(0, 3000), soapEnvelope: soapEnvelope.substring(0, 4000) });
    }

    // SOAP 1.1 — SEFAZ NFeRecepcaoEvento4
    // SOAPAction correto: nfeRecepcaoEventoNF (com sufixo NF), não nfeRecepcaoEvento
    // Header: nfeCabecMsg com cUF=91 (AN) e versaoDados=1.00 — obrigatório, senão "Object reference not set"
    // Body: nfeRecepcaoEventoNF > nfeDadosMsg > signed XML
    const soapEnvelope =
      '<?xml version="1.0" encoding="UTF-8"?>' +
      '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">' +
      '<soap:Header>' +
      '<nfeCabecMsg xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4">' +
      '<cUF>91</cUF>' +
      '<versaoDados>1.00</versaoDados>' +
      '</nfeCabecMsg>' +
      '</soap:Header>' +
      '<soap:Body>' +
      '<nfeRecepcaoEventoNF xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4">' +
      '<nfeDadosMsg>' +
      signedXml +
      '</nfeDadosMsg>' +
      '</nfeRecepcaoEventoNF>' +
      '</soap:Body>' +
      '</soap:Envelope>';

    const manifestacaoOptions = {
      host: "www.nfe.fazenda.gov.br",
      path: "/NFeRecepcaoEvento4/NFeRecepcaoEvento4.asmx",
      action: "http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4/nfeRecepcaoEventoNF",
      soapVersion: "1.1",
    };
    console.log("[manifestacao] SOAP 1.1 → host:", manifestacaoOptions.host, "path:", manifestacaoOptions.path, "action:", manifestacaoOptions.action);

    try {
      const responseXml = await sendToSefaz(soapEnvelope, certPem, keyPem, manifestacaoOptions);
      res.json({ xml: responseXml });
    } catch (sefazError) {
      console.log("[manifestacao] Erro SEFAZ:", sefazError.message);
      res.status(500).json({ 
        error: sefazError.message,
        host: manifestacaoOptions.host,
        path: manifestacaoOptions.path,
        proxyVersion: "2.2.0-soap11"
      });
    }
  } catch (error) {
    console.error("Erro no proxy manifestação:", error.message);
    res.status(500).json({ error: error.message });
  }
});

app.get("/health", (req, res) => res.json({ ok: true }));
app.get("/version", (req, res) => res.json({ ok: true, version: "2.5.0-debug", manifestacaoHost: "www.nfe.fazenda.gov.br", soapAction: "nfeRecepcaoEventoNF", soapVersion: "1.1", hasCabecMsg: true, hasDebug: true, deployTime: new Date().toISOString() }));

app.listen(PORT, () => {
  console.log(`Proxy SEFAZ rodando na porta ${PORT}`);
});