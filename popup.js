document.addEventListener('DOMContentLoaded', () => {
  const pemFileElement = document.getElementById('pemFile');
  const pemDataElement = document.getElementById('pemData');

  // Format a date string into "YYYY-MM-DD HH:MM:SS" format.
  const formatDate = (dateStr) => {
    if (!dateStr) return dateStr;
    // Remove trailing "Z" if present.
    dateStr = dateStr.endsWith("Z") ? dateStr.slice(0, -1) : dateStr;
    // UTCTime format: YYMMDDHHMMSS
    if (dateStr.length === 12) {
      let year = parseInt(dateStr.substring(0, 2), 10);
      year = year < 50 ? 2000 + year : 1900 + year;
      const month = dateStr.substring(2, 4);
      const day = dateStr.substring(4, 6);
      const hour = dateStr.substring(6, 8);
      const minute = dateStr.substring(8, 10);
      const second = dateStr.substring(10, 12);
      return `${year}-${month}-${day} ${hour}:${minute}:${second}`;
    } 
    // Generalized Time format: YYYYMMDDHHMMSS
    else if (dateStr.length === 14) {
      const year = dateStr.substring(0, 4);
      const month = dateStr.substring(4, 6);
      const day = dateStr.substring(6, 8);
      const hour = dateStr.substring(8, 10);
      const minute = dateStr.substring(10, 12);
      const second = dateStr.substring(12, 14);
      return `${year}-${month}-${day} ${hour}:${minute}:${second}`;
    }
    return dateStr;
  };

  // Generate HTML for displaying parsed PEM data.
  const generateDisplayHTML = (parsedData) => {
    let html = '<h2>PEM Parsing Result</h2>';
    if (parsedData.error) {
      html += `<p style="color:red;"><strong>Error:</strong> ${parsedData.error}</p>`;
    } else {
      html += '<ul>';
      for (const key in parsedData) {
        html += `<li><strong>${key}:</strong> ${parsedData[key]}</li>`;
      }
      html += '</ul>';
    }
    return html;
  };

  // Parse PEM data and display results.
  const parseAndDisplayPEM = (pemData) => {
    try {
      const parsedData = {};

      if (pemData.includes("-----BEGIN CERTIFICATE-----")) {
        const cert = new jsrsasign.X509();
        cert.readCertPEM(pemData);
        parsedData.subject = cert.getSubjectString();
        parsedData.issuer = cert.getIssuerString();
        parsedData.version = cert.getVersion();
        parsedData.serialNumber = cert.getSerialNumberHex();
        parsedData.notBefore = formatDate(cert.getNotBefore());
        parsedData.notAfter = formatDate(cert.getNotAfter());

        const pubkey = cert.getPublicKey();
        if (pubkey) {
          if (pubkey.n) {
            parsedData.publicKeyAlgorithm = "RSA";
            if (typeof pubkey.n.bitLength === "function") {
              parsedData.publicKeyLength = pubkey.n.bitLength();
            }
          } else if (pubkey.ecparams) {
            parsedData.publicKeyAlgorithm = "ECDSA";
            const ecdsaKeyLengths = {
              "secp256r1": 256,
              "secp384r1": 384,
              "secp521r1": 521
            };
            if (pubkey.ecparams) {
              // Retrieve curve name from ecparams.name or pubkey.curve.
              const curveName = (pubkey.ecparams.name || pubkey.curve) || "Unknown";
              parsedData.publicKeyLength = ecdsaKeyLengths[curveName] || "Unknown";
            }
          } else {
            parsedData.publicKeyAlgorithm = "Unknown";
          }
        }

        const keyUsage = (typeof cert.getExtKeyUsageString === "function") ? cert.getExtKeyUsageString() : null;
        if (keyUsage) {
          parsedData.keyUsage = keyUsage;
        }

        const extKeyUsage = (typeof cert.getExtExtKeyUsage === "function") ? cert.getExtExtKeyUsage() : null;
        if (extKeyUsage) {
          parsedData.extKeyUsage = (typeof extKeyUsage === "object") ? JSON.stringify(extKeyUsage.array, null, 2) : extKeyUsage;
        }

        const sigAlg = cert.getSignatureAlgorithmName();
        if (sigAlg) {
          parsedData.signatureAlgorithm = sigAlg;
          parsedData.hashAlgorithm = sigAlg.split("with")[0] || sigAlg;
        }

        const sans = cert.getExtSubjectAltName();
        if (sans) {
          if (typeof sans === "object" && sans.array) {
            let sanOutput = "<ul>";
            sans.array.forEach(item => {
              sanOutput += `<li>${JSON.stringify(item, null, 2)}</li>`;
            });
            sanOutput += "</ul>";
            parsedData.subjectAltNames = sanOutput;
          } else if (Array.isArray(sans)) {
            parsedData.subjectAltNames = `<ul><li>${sans.join(", ")}</li></ul>`;
          } else {
            parsedData.subjectAltNames = sans;
          }
        }
      } else if (pemData.includes("PRIVATE KEY")) {
        parsedData.type = "Private Key";
      } else if (pemData.includes("-----BEGIN CERTIFICATE REQUEST-----")) {
        const params = jsrsasign.KJUR.asn1.csr.CSRUtil.getParam(pemData);
        parsedData.subject = JSON.stringify(params.subject?.str, null, 2);
        parsedData.signatureAlgorithm = params.sigalg.split("with")[1] || params.sigalg;
        parsedData.hashAlgorithm = params.sigalg.split("with")[0] || params.sigalg;

        if (params.extreq) {
          const sanExt = params.extreq.find(ext => ext.extname === "subjectAltName");
          if (sanExt && sanExt.array) {
            parsedData.subjectAltNames = sanExt.array.map(item => {
              if (item.dns) {
                return `DNS: ${item.dns}`;
              } else if (item.rfc822) {
                return `Email: ${item.rfc822}`;
              } else if (item.uri) {
                return `URI: ${item.uri}`;
              } else if (item.ip) {
                return `IP: ${item.ip}`;
              } else {
                return JSON.stringify(item);
              }
            }).join(", ");
          }
        }
      } else {
        parsedData.error = "Invalid PEM data";
      }
      pemDataElement.innerHTML = generateDisplayHTML(parsedData);
    } catch (error) {
      console.error("Error parsing PEM data:", error);
      pemDataElement.innerHTML = `<p style="color:red;">Error parsing PEM data: ${error.message}</p>`;
    }
  };

  // Event handler for PEM file selection.
  pemFileElement.addEventListener('change', (event) => {
    const file = event.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        parseAndDisplayPEM(e.target.result);
      };
      reader.readAsText(file);
    }
  });

  // Listen for messages from the extension to parse PEM data.
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "parsePEMData") {
      parseAndDisplayPEM(request.pemData);
      sendResponse({ success: true });
    }
  });
});