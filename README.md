# CharJeff
const KEEPALIVE_URL = "https://cloudinfra-gw-us.portal.checkpoint.com/app/endpoint-web-mgmt/harmony/endpoint/api/v1/session/keepalive";
const LOGIN_URL = "https://cloudinfra-gw-us.portal.checkpoint.com/app/endpoint-web-mgmt/harmony/endpoint/api/v1/session/login/cloud";
const AUTH_URL = "https://cloudinfra-gw-us.portal.checkpoint.com/auth/external";
const CLIENT_ID = "67f7028910e9481d91380127ffcaf46d";
const ACCESS_KEY = "7d36e64ca58945ea98ab848ecff2e4d0";
const TOKEN_EXPIRATION_TIME = 300; 

function fetchWithRetries(url, options, retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      const response = UrlFetchApp.fetch(url, options);
      return response;
    } catch (error) {
      console.error(`Intento ${i + 1} fallido: ${error.message}`);
      if (i === retries - 1) throw error;
      Utilities.sleep(1000); 
    }
  }
}

function getBearerToken() {
  const cache = CacheService.getScriptCache();
  let token = cache.get("bearerToken");
  let tokenTime = cache.get("bearerTokenTime");
  
  // Verificar si el token en caché es válido o ha caducado
  if (token && tokenTime && (new Date().getTime() - tokenTime < TOKEN_EXPIRATION_TIME * 1000)) {
    console.log("Usando Bearer Token en caché.");
    return token;
  }

  console.log("Bearer Token caducado o no encontrado. Obteniendo uno nuevo...");
  const payload = {
    clientId: CLIENT_ID,
    accessKey: ACCESS_KEY,
  };

  const options = {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(payload),
    muteHttpExceptions: true,
  };

  try {
    const response = fetchWithRetries(AUTH_URL, options);
    if (response.getResponseCode() === 200) {
      const data = JSON.parse(response.getContentText());
      token = data.data?.token;

      if (token) {
        // Actualizar el caché
        cache.put("bearerToken", token, TOKEN_EXPIRATION_TIME); // Guardar en caché por 5 minutos
        cache.put("bearerTokenTime", new Date().getTime(), TOKEN_EXPIRATION_TIME); // Marca de tiempo
        console.log("Bearer Token obtenido y almacenado en caché.");
        return token;
      }
    }
    console.error("No se pudo obtener el Bearer Token.");
  } catch (error) {
    console.error("Error al obtener el Bearer Token:", error.message);
  }
  return null;
}

function startSession(bearerToken) {
  if (!bearerToken) {
    console.error("Bearer Token no válido.");
    return null;
  }

  const cache = CacheService.getScriptCache();
  let apiToken = cache.get("apiToken");
  let apiTokenTime = cache.get("apiTokenTime");

  // Verificar si el apiToken ha caducado
  if (apiToken && apiTokenTime && (new Date().getTime() - apiTokenTime < TOKEN_EXPIRATION_TIME * 1000)) {
    console.log("Usando API Token en caché.");
    return apiToken;
  }

  console.log("API Token caducado o no encontrado. Obteniendo uno nuevo...");
  const options = {
    method: "post",
    headers: {
      "Authorization": `Bearer ${bearerToken}`,
      "accept": "*/*"
    },
    muteHttpExceptions: true,
  };

  try {
    const response = fetchWithRetries(LOGIN_URL, options);
    console.log("Contenido de la respuesta:", response.getContentText());
    if (response.getResponseCode() === 201) {
      const data = JSON.parse(response.getContentText());
      apiToken = data.apiToken;

      if (apiToken) {
        // Guardar apiToken en caché
        cache.put("apiToken", apiToken, TOKEN_EXPIRATION_TIME); 
        cache.put("apiTokenTime", new Date().getTime(), TOKEN_EXPIRATION_TIME); 
        console.log("API Token obtenido y almacenado en caché.");
        return apiToken;
      }
    }
    console.error("Error al iniciar sesión.");
  } catch (error) {
    console.error("Error al iniciar sesión:", error.message);
  }
  return null;
}

function keepSessionAlive(apiToken) {
  if (!apiToken) {
    console.error("No se proporcionó un API Token para mantener la sesión activa.");
    return;
  }

  const options = {
    method: "post",
    headers: {
      "Authorization": `Bearer ${getBearerToken()}`,
      "x-mgmt-api-token": apiToken,
      "accept": "*/*"
    },
  };

  try {
    const response = fetchWithRetries(KEEPALIVE_URL, options);
    if (response.getResponseCode() === 204) {
      console.log("Sesión extendida correctamente.");
    } else {
      console.error(`Error al mantener la sesión activa: ${response.getContentText()}`);
    }
  } catch (error) {
    console.error("Error al mantener la sesión activa:", error.message);
  }
}

function initializeAndMaintainSession() {
  try {
    const bearerToken = getBearerToken();
    if (!bearerToken) {
      console.error("No se pudo obtener el Bearer Token.");
      return;
    }

    const apiToken = startSession(bearerToken);
    if (!apiToken) {
      console.error("No se pudo obtener el API Token.");
      return;
    }

    const existingTriggers = ScriptApp.getProjectTriggers();
    const triggerExists = existingTriggers.some(t => t.getHandlerFunction() === "keepSessionAliveTrigger");

    if (!triggerExists) {
      ScriptApp.newTrigger("keepSessionAliveTrigger")
        .timeBased()
        .everyMinutes(5)
        .create();
      console.log("Disparador de sesión creado.");
    }

   return [bearerToken, apiToken ];
  } catch (error) {
    console.error("Error en el flujo de inicialización:", error.message);
  }
}

function keepSessionAliveTrigger() {
  const cache = CacheService.getScriptCache();
  const apiToken = cache.get("apiToken");
  if (apiToken) {
    keepSessionAlive(apiToken);
  } else {
    console.error("El token de sesión expiró. Reautenticando...");
    initializeAndMaintainSession();
  }
}

function testCompleteFlow() {
  const [bearerToken, apiToken] = initializeAndMaintainSession();
  console.log("Bearer Token:", bearerToken);
  console.log("API Token:", apiToken);
}
const AUTH_URL_IOC = "https://cloudinfra-gw-us.portal.checkpoint.com/auth/external"; 
const CLIENT_ID_IOC = "9550d5dfd0f641679a7dd28f1d56d663";
const SECRET_KEY_IOC = "ee91bc8401de477085bd1ff43470fda9";
const TOKEN_EXPIRATION_TIME_IOC = 999; // 30 minutos (1800 segundos)

function fetchWithRetriesIoc(url, options, retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      const response = UrlFetchApp.fetch(url, options);
      return response;
    } catch (error) {
      console.error(`Intento ${i + 1} fallido: ${error.message}`);
      if (i === retries - 1) throw error;
      Utilities.sleep(1000);
    }
  }
}

function getBearerTokenIoc() {
  const cache = CacheService.getScriptCache();
  let token = cache.get("bearerTokenIoc");
  let tokenTime = cache.get("bearerTokenTimeIoc");

  // Verifica si el token aún es válido
  if (token && tokenTime && (new Date().getTime() - tokenTime < TOKEN_EXPIRATION_TIME_IOC * 1000)) {
    console.log("Usando Bearer Token en caché.");
    return token;
  }

  console.log("Obteniendo un nuevo Bearer Token...");
  const payload = {
    clientId: CLIENT_ID_IOC,
    accessKey: SECRET_KEY_IOC
  };

  const options = {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  };

  try {
    const response = fetchWithRetriesIoc(AUTH_URL_IOC, options);
    if (response.getResponseCode() === 200) {
      const data = JSON.parse(response.getContentText());
      token = data.data?.token;

      if (token) {
        cache.put("bearerTokenIoc", token, TOKEN_EXPIRATION_TIME_IOC);
        cache.put("bearerTokenTimeIoc", new Date().getTime(), TOKEN_EXPIRATION_TIME_IOC);
        console.log("Bearer Token obtenido y almacenado.");
        return token;
      }
    }
    console.error("Error al obtener el Bearer Token.");
  } catch (error) {
    console.error("Error en la autenticación:", error.message);
  }
  return null;
}

const AUTH_URL_EVENT = "https://cloudinfra-gw-us.portal.checkpoint.com/auth/external"; 
const CLIENT_ID_EVENT = "b781e0ae500c4e0b882289c45c78a065";
const SECRET_KEY_EVENT = "684ac09f623a4964a57e5808a8f05d67";
const TOKEN_EXPIRATION_TIME_EVENT = 999; // 30 minutos (1800 segundos)

function fetchWithRetriesEvent(url, options, retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      const response = UrlFetchApp.fetch(url, options);
      return response;
    } catch (error) {
      console.error(`Intento ${i + 1} fallido: ${error.message}`);
      if (i === retries - 1) throw error;
      Utilities.sleep(1000);
    }
  }
}

function getBearerTokenEvent() {
  const cache = CacheService.getScriptCache();
  let token = cache.get("bearerTokenEvent");
  let tokenTime = cache.get("bearerTokenTimeEvent");

  // Verifica si el token aún es válido
  if (token && tokenTime && (new Date().getTime() - tokenTime < TOKEN_EXPIRATION_TIME_EVENT * 1000)) {
    console.log("Usando Bearer Token en caché.");
    return token;
  }

  console.log("Obteniendo un nuevo Bearer Token...");
  const payload = {
    clientId: CLIENT_ID_EVENT,
    accessKey: SECRET_KEY_EVENT
  };

  const options = {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  };

  try {
    const response = fetchWithRetriesIoc(AUTH_URL_IOC, options);
    if (response.getResponseCode() === 200) {
      const data = JSON.parse(response.getContentText());
      token = data.data?.token;

      if (token) {
        cache.put("bearerTokenEvent", token, TOKEN_EXPIRATION_TIME_IOC);
        cache.put("bearerTokenTimeEvent", new Date().getTime(), TOKEN_EXPIRATION_TIME_IOC);
        console.log("Bearer Token obtenido y almacenado.");
        return token;
      }
    }
    console.error("Error al obtener el Bearer Token.");
  } catch (error) {
    console.error("Error en la autenticación:", error.message);
  }
  return null;
}

function fetchLogs(dateRange = null, timeRange = null) {
  console.log(`Buscando logs para el rango de fechas: ${dateRange || 'Últimas 24 horas'}`);

  const token = getBearerTokenEvent();
  if (!token) {
    console.error("No se pudo obtener el Bearer Token.");
    return null;
  }

  let startTime, endTime;
  const now = new Date();

  if (dateRange) {
    const [start, end] = dateRange.split(":");

    if (timeRange) {
      startTime = `${start}T${timeRange.start}Z`;
      endTime = end ? `${end}T${timeRange.end}Z` : now.toISOString();
    } else {
      startTime = `${start}T00:00:00Z`;
      endTime = `${end}T23:59:59Z`;
    }
  } else {
    endTime = now.toISOString();
    startTime = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
  }

  // Filtros
  const severityFilter = !timeRange ? '(severity:"High" OR severity:"Critical")' : '(severity:"High" OR severity:"Critical")';
  const eventTypeFilter = '(event_type:"TE Event" OR event_type:"Forensics Case Analysis")';
  const filtering = `${severityFilter} AND ${eventTypeFilter}`;

  const apiUrl = "https://cloudinfra-gw-us.portal.checkpoint.com/app/laas-logs-api/api/logs_query";
  console.log(`Rango de tiempo: ${startTime} - ${endTime}`);

  const requestBody = {
    filter: filtering,
    limit: 5000,
    pageLimit: 100,
    cloudService: "Harmony Endpoint",
    timeframe: {
      startTime: startTime,
      endTime: endTime
    }
  };

  const options = {
    method: "post",
    headers: {
      "Authorization": `Bearer ${token}`,
      "Accept": "application/json",
      "Content-Type": "application/json"
    },
    payload: JSON.stringify(requestBody),
    muteHttpExceptions: true
  };

  try {
    const response = UrlFetchApp.fetch(apiUrl, options);
    const responseData = JSON.parse(response.getContentText());

    if (response.getResponseCode() === 200 && responseData.success) {
      const taskId = responseData.data.taskId;
      console.log(`Recuperando logs para taskId: ${taskId}`);

      return getPageToken(taskId, token);
    } else {
      console.error("Error en la búsqueda de logs:", responseData);
      return null;
    }
  } catch (error) {
    console.error("Error en la solicitud:", error.message);
    return null;
  }
}

function getPageToken(taskId, token, retries = 10) {
  const checkUrl = `https://cloudinfra-gw-us.portal.checkpoint.com/app/laas-logs-api/api/logs_query/${taskId}`;

  for (let i = 0; i < retries; i++) {
    const options = {
      method: "get",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Accept": "application/json"
      },
      muteHttpExceptions: true
    };

    try {
      const response = UrlFetchApp.fetch(checkUrl, options);
      const responseData = JSON.parse(response.getContentText());

      if (response.getResponseCode() === 200 && responseData.success) {
        const state = responseData.data.state;
        console.log(`Estado de la búsqueda: ${state}`);

        if (state === "Ready" || state === "Done") {
          const pageTokens = responseData.data.pageTokens;
          if (pageTokens && pageTokens.length > 0) {
            console.log(`pageToken obtenido: ${pageTokens[0]}`);
            console.log(responseData.data);
            return retrieveLogs(taskId, token, pageTokens[0]);
          } else {
            console.warn("📭 La consulta se completó, pero no se encontraron logs en el rango especificado.");
            return [];
          }
        } else if (state === "Failed") {
          console.error("La búsqueda de logs falló.");
          return null;
        }
      } else {
        console.error("Error al obtener pageToken:", responseData);
        return null;
      }

      console.log("Esperando 1 segundo antes de reintentar...");
      Utilities.sleep(1000);
    } catch (error) {
      console.error("Error en la solicitud:", error.message);
      return null;
    }
  }

  console.error("Tiempo de espera agotado. La búsqueda aún no se completó.");
  return null;
}

function retrieveLogs(taskId, token, pageToken, accumulatedLogs = [], retries = 3) {
  const retrieveUrl = "https://cloudinfra-gw-us.portal.checkpoint.com/app/laas-logs-api/api/logs_query/retrieve";
  const requestBody = {
    taskId: taskId,
    pageToken: pageToken
  };

  const options = {
    method: "post",
    headers: {
      "Authorization": `Bearer ${token}`,
      "Accept": "application/json",
      "Content-Type": "application/json"
    },
    payload: JSON.stringify(requestBody),
    muteHttpExceptions: true
  };
  
  try {
    const response = UrlFetchApp.fetch(retrieveUrl, options);
    const responseText = response.getContentText().trim();
    let responseData;
    
    if (responseText) {
      responseData = JSON.parse(response.getContentText());
      console.log(responseData);
    }

    if (response.getResponseCode() === 200 && responseData.success) {
      console.log(`Página recibida con ${responseData.data.records.length} registros`);

      accumulatedLogs.push(...responseData.data.records);

      if (responseData.data.nextPageToken && responseData.data.nextPageToken !== "NULL") {
        console.log("Recuperando siguiente página...");
        return retrieveLogs(taskId, token, responseData.data.nextPageToken, accumulatedLogs);
      }else {
        console.log(`🔍 Recuperación finalizada. Total de registros: ${accumulatedLogs.length}`);
        return accumulatedLogs;
      }
    }else if (response.getResponseCode() === 503 && retries > 0) {
        console.log("⚠️ Error 503 recibido. Intentando nuevamente...");
        Utilities.sleep(1500); // Esperar 1 segundos antes de reintentar
        return retrieveLogs(taskId, token, pageToken, accumulatedLogs, retries - 1); // Reintentar 
    }else {
      console.error("Error al recuperar logs:", responseData);
      return accumulatedLogs;
    }
  } catch (error) {
    console.error("Error en la solicitud:", error.message);
    return accumulatedLogs;
  }
}



function fetchRecentLogs() {
  const now = new Date();
  const startTime = new Date(now.getTime() - 5 * 60 * 1000); // Últimos 5 minutos

  // Formatear la fecha y hora en formato ISO 8601
  const formattedDate = formatDate(now).split("T")[0]; // Formato YYYY-MM-DD
  const formattedTimeRange = {
    start: formatTime(startTime), // Formato HH:mm:ss
    end: formatTime(now) // Formato HH:mm:ss
  };

  console.log(`Buscando logs para los últimos 5 minutos: ${formattedDate} ${formattedTimeRange.start} - ${formattedTimeRange.end}`);
  return fetchLogs(formattedDate, formattedTimeRange);
}

function sendToGoogleChatWebhook() {
  const webhookUrl = "https://chat.googleapis.com/v1/spaces/AAAAAeV3UvE/messages?key=AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI&token=f9-0PM3V0Sa0gkFw2dpzpT77AW9yuR4ifNmWSBfnIAo";
  let logs = fetchRecentLogs();
  if (!logs) { return null; }
  logs = filterLogs(logs);
  logs.reverse();

  logs.forEach((log, index) => {
    console.log(`📨 Enviando mensaje ${index + 1} de ${logs.length}`);

    // Formatear la fecha
    const formattedDate = formatIso(log.time);

    const event = {
      "Forensics Case Analysis": "Forensics",
      "TE Event": "Thread Emulation"
    };

    // Recortar la fuente si es muy larga
    const source = log.resource?.[0] || log.file_name?.[0] || "N/A";
    const truncatedSource = source.length > 150 ? source.substring(0, 147) + "..." : source;
    let policy = log.policy_name.replace(/\s*\(.*\)$/, '').trim();
    const hash = log.file_sha1 || log.file_md5 || null;

    // **🔍 Verificación en VirusTotal antes de enviar**
    let vtAnalysis = checkVirusTotal(source, hash);

    // **📌 Construcción del mensaje**
    let message = `🚨 *Evento de Seguridad* 🚨\n\n`;
    message += `  - 🗓️ *Fecha y Hora:* ${formattedDate}\n`;
    message += `  - ⚠️ *Tipo de Evento:* ${event[log.event_type]}\n`;
    message += `  - 🛡️ *Tipo de Protección:* ${log.protection_type}\n`;
    message += `  - 🔥 *Severidad:* ${log.severity}\n`;
    message += `  - ⚙️ *Acción de Harmony:* ${log.action}\n`;
    message += `  - 💻 *Equipo:* ${log.src_machine_name.replace(/.bop.local\s*/g, '')}\n`;
    message += `  - 🌐 *IP:* ${log.src}\n`;
    message += `  - 📜 *Política:* ${policy}\n`;
    message += `  - 👤 *Usuario:* ${log.src_user_name[0]}\n`;
    message += `  - 🔗 *Fuente:* ${truncatedSource}\n`;

    // Mostrar hash solo si está presente
    if (hash) {
      message += `  - 🔐 *Hash:* ${hash}\n`;
    }

    // **🔍 Agregar resultado de VirusTotal al mensaje**
    if (vtAnalysis) {
      message += `\n🦠 *Reporte de VirusTotal:*\n`;
      message += `  - 🧪 *Detecciones:* ${vtAnalysis.detections}\n`;
      message += `  - 🔬 *Veredicto:* ${vtAnalysis.verdict}\n`;
      message += `  - 📄 *Detalles:* ${vtAnalysis.url}\n`;
    } else {
      message += `\n🦠 *Reporte de VirusTotal:* No se encontraron registros.\n`;
    }

    // **📩 Enviar mensaje**
    const payload = { text: message };
    const options = {
      method: "post",
      contentType: "application/json",
      payload: JSON.stringify(payload),
      muteHttpExceptions: true
    };

    try {
      UrlFetchApp.fetch(webhookUrl, options);
      console.log(`✅ Mensaje ${index + 1} enviado a Google Chat.`);
      Utilities.sleep(500);
    } catch (error) {
      console.error(`❌ Error al enviar el mensaje ${index + 1}:`, error.message);
    }
  });

  saveLogsToSheet(logs);
  generateGraphic();
}

// 📊 Guardar logs en Google Sheets y generar link de descarga
function handleAccessLogs(witResponse) {
  let logsKeyword = null;

  // Buscar la entidad 'fecha'
  for (let key of Object.keys(witResponse.entities)) {
    if (key.startsWith("fecha")) {
      logsKeyword = witResponse.entities[key][0]?.value;
      break;
    }
  }

  if (!logsKeyword) {
    return { text: "No especificaste una fecha válida." };
  }

  const cleanKeyword = logsKeyword.replace(/^\(|\)$/g, '');
  const result = fetchLogs(cleanKeyword); // Obtener logs

  if (result) {
    const responseMessage = generateCsvDownload(result); // Guardar en Sheet y generar respuesta
    console.log(responseMessage);
    return responseMessage;
  } else {
    console.log("No se pudieron obtener los logs.");
    return "No se pudieron obtener los logs.";
  }
}

function generateCsvDownload(logs) {
  if (!logs || logs.length === 0) return "No se encontraron logs.";

  logs = filterLogs(logs);
  logs.reverse();

  let csvContent = convertToCSV(logs); // Usamos la misma estructura para consistencia

  let fileId = Utilities.getUuid(); // Generar un ID único
  CacheService.getScriptCache().put(fileId, csvContent, 3600); // Guardar CSV en caché (1h)

  let scriptUrl = "https://script.google.com/macros/s/AKfycbwyhZm0-yEYnqO2HoGP7G9euIGCGEeyNS20xN5s8BMpPPhMxCeGhpkGfXhdXyU54cYaXQ/exec";
  return `📂 Aquí están los logs: ${scriptUrl}?file=${fileId}`;
}

// 🔹 Servir el archivo cuando el usuario acceda al enlace
function doGet(e) {
  const cache = CacheService.getScriptCache();
  let fileId = e.parameter.file;
  let format = e.parameter.format || "html"; // "csv" o "html"

  if (!fileId) {
    return ContentService.createTextOutput("❌ Error: No se proporcionó un ID de archivo.");
  }

  let fileData = cache.get(fileId);
  if (!fileData) {
    return ContentService.createTextOutput("❌ Error: El archivo ha expirado o no existe.");
  }

  if (format === "csv") {
    return ContentService.createTextOutput(fileData).setMimeType(ContentService.MimeType.PLAIN_TEXT);
  } else {
    return HtmlService.createHtmlOutput(generateHtmlTable(fileData));
  }
}


// 📌 Función para convertir JSON a CSV estructurado
function convertToCSV(logs) {
  if (!logs || logs.length === 0) return "No hay datos disponibles.";

  let headers = ["Fecha y Hora", "Tipo de Evento", "Protección", "Severidad", "Acción de Harmony",
                 "Equipo", "IP", "Política", "Usuario", "Fuente", "Hash"];
  
  let csvArray = [];
  csvArray.push(headers.join(",")); // Añadir encabezados

  logs.forEach(log => {
    // Formateamos la fecha y hora
    let formattedDate = formatIso(log.time);

    // Mapeamos los tipos de eventos a nombres más amigables
    const event = {
      "Forensics Case Analysis": "Forensics",
      "TE Event": "Thread Emulation"
    };

    // Recortar la fuente si es muy larga
    const source = log.resource?.[0] || log.file_name?.[0] || "N/A";
    const truncatedSource = source.length > 150 ? source.substring(0, 147) + "..." : source;
    let policy = log.policy_name.replace(/\s*\(.*\)$/, '').trim();
    const hash = log.file_sha1 || log.file_md5 || null;

    // Aseguramos que la fila esté bien estructurada para el CSV
    let row = [
      formattedDate || "N/A",
      event[log.event_type] || "N/A",
      log.protection_type || "N/A",
      log.severity || "N/A",
      log.action || "N/A",
      log.src_machine_name ? log.src_machine_name.replace(/.bop.local\s*/g, '') : "N/A",
      log.src || "N/A",
      policy || "N/A",
      log.src_user_name ? log.src_user_name[0] : "N/A",
      truncatedSource || "N/A",
      hash || "N/A"
    ];

    // Aseguramos formato CSV válido con comillas para evitar problemas con comas o saltos de línea
    row = row.map(value => `"${String(value).replace(/"/g, '""')}"`);
    csvArray.push(row.join(",")); // Convertimos la fila a formato CSV
  });

  return csvArray.join("\n"); // Unimos todas las filas con salto de línea
}



function generateHtmlTable(csvData) {
  let rows = csvData.split("\n").map(row => row.split(","));
  let headers = rows.shift(); // Extraer encabezados

  let html = `
    <html>
    <head>
      <title>Logs de Seguridad</title>
      <style>
        body { font-family: Arial, sans-serif; padding: 20px; margin: 0; }
        h2 { text-align: center; color: #333; }
        .container { max-width: 95%; margin: auto; overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; table-layout: fixed; }
        th, td { padding: 12px; border: 1px solid #ddd; word-wrap: break-word; }
        th { background-color: #4CAF50; color: white; cursor: pointer; text-align: left; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        input { width: 100%; padding: 8px; margin-bottom: 10px; border: 1px solid #ddd; }
        .btn { padding: 10px 20px; background: #4CAF50; color: white; border: none; cursor: pointer; margin-top: 10px; }
        .btn:hover { background: #45a049; }
      </style>
    </head>
    <body>
      <div class="container">
        <h2>📊 Logs de Seguridad</h2>
        <input type="text" id="searchBox" placeholder="🔍 Buscar logs..." onkeyup="filterTable()">
        <table id="logsTable">
          <thead>
            <tr>${headers.map(header => `<th onclick="sortTable(this)">${header}</th>`).join("")}</tr>
          </thead>
          <tbody>
            ${rows.map(row => `<tr>${row.map(cell => `<td>${cell}</td>`).join("")}</tr>`).join("")}
          </tbody>
        </table>
        
      </div>
      <script>
        function filterTable() {
          let input = document.getElementById("searchBox").value.toLowerCase();
          let rows = document.querySelectorAll("#logsTable tbody tr");
          rows.forEach(row => {
            row.style.display = row.innerText.toLowerCase().includes(input) ? "" : "none";
          });
        }
        function sortTable(header) {
          let table = document.getElementById("logsTable");
          let rows = Array.from(table.rows).slice(1);
          let index = Array.from(header.parentElement.children).indexOf(header);
          let ascending = header.dataset.ascending === "true";
          header.dataset.ascending = !ascending;
          rows.sort((a, b) => (ascending ? a.cells[index].innerText.localeCompare(b.cells[index].innerText) : b.cells[index].innerText.localeCompare(a.cells[index].innerText)));
          rows.forEach(row => table.appendChild(row));
        }
      </script>
    </body>
    </html>
  `;
  return html;
}


function filterLogs(logs) {
  if (!logs){return null};
  const regexExclude = /^C:\\Windows\\Installer\\.*\.msi$/; // Excluir archivos MSI en C:\Windows\Installer
  const excludedSources = getExcludedSources(); // Obtener lista de fuentes excluidas

  return logs.filter((log, index) => {
    const source = log.resource?.[0] || log.file_name?.[0] || "N/A";
    const description = log.description || "";
    const user = log.src_user_name?.[0] || "";
    const machine = log.src_machine_name?.replace(/.bop.local\s*/g, '') || "";

    // Filtros de exclusión
    const isBlocked = description.includes("Attack status: Blocked"); // Excluir logs bloqueados
    const isMsiFile = regexExclude.test(source); // Excluir archivos MSI en C:\Windows\Installer
    const isExcludedSource = excludedSources.some(exclusion => 
      source.toLowerCase().includes(exclusion.toLowerCase())
    ); // Excluir fuentes en la lista
    const isInvalidUser = !/^\d+$/.test(user) && user.toLowerCase() !== "ntlocal"; // Excluir si no es numérico ni "ntlocal"
    const isPEPmachine = machine.startsWith("PEP"); // Excluir equipos que comienzan con "PEP"

    if (isInvalidUser) {
      console.log(`⏩ Log ${index + 1} ignorado (usuario inválido: "${user}")`);
    }
    if (isPEPmachine) {
      console.log(`⏩ Log ${index + 1} ignorado (equipo excluido: "${machine}")`);
    }

    // Si cumple alguna condición de exclusión, se elimina
    return !(isBlocked || isMsiFile || isExcludedSource || isInvalidUser || isPEPmachine);
  });
}
function fetchIoc(ioc) {
  console.log(`Búsqueda de datos para el IOC: ${ioc}`);

  const token = getBearerTokenIoc();
  if (!token) {
    console.error("No se pudo obtener el Bearer Token.");
    return null;
  }
  
  // Convertir el IOC a Base64 si es necesario
  const encodedIoc = Utilities.base64Encode(ioc).replace(/\n/g, '');
  const apiUrl = `https://cloudinfra-gw-us.portal.checkpoint.com/app/ioc-management/indicators/search?limit=20&offset=0&text=${encodedIoc}`;


  const options = {
    method: "get",
    headers: {
      "Authorization": `Bearer ${token}`,
      "Accept": "application/json"
    },
    muteHttpExceptions: true
  };

  try {
    const response = UrlFetchApp.fetch(apiUrl, options);
    const responseCode = response.getResponseCode();
    const responseData = response.getContentText();

    console.log(`Código de respuesta: ${responseCode}`);
    console.log(`Datos de respuesta: ${responseData}`);

    if (responseCode === 200) {
      const data = JSON.parse(responseData);
      if (data.indicators && data.indicators.length > 0) {
        console.log("Datos del indicador:", JSON.stringify(data.indicators, null, 2));
        return data.indicators;
      } else {
        console.log(`El indicador ${ioc} no se encuentra en la base de datos.`);
        return null;
      }
    } else if (responseCode === 401) {
      console.error("Error 401: Token de autenticación inválido o expirado.");
    } else if (responseCode === 403) {
      console.error("Error 403: Permisos insuficientes.");
    } else if (responseCode === 404) {
      console.error("Error 404: IOC no encontrado.");
    } else {
      console.error(`Error en la solicitud (${responseCode}): ${responseData}`);
    }
    
    return null;
  } catch (error) {
    console.error("Error en la solicitud:", error.message);
    return null;
  }
}


function handleAccessIoc(witResponse) {
  let iocKeyword = null;

  // Buscar la entidad 'ioc'
  for (let key of Object.keys(witResponse.entities)) {
    if (key.startsWith("ioc")) {
      iocKeyword = witResponse.entities[key][0]?.value;
      break;
    }
  }

  if (!iocKeyword) {
    return { text: "no especificaste un Ioc valido." };
  }

  const cleanIoc = iocKeyword.replace(/^\$/, ''); 

  const result = fetchIoc(cleanIoc);

  if (result) {
    const responseMessage = iocInfoTemplate(result);
    console.log(responseMessage);
    return responseMessage;
  } else {
    console.log("No se encontró información para el IOC.");
    return `no se encontro el indicador ${cleanIoc} en la base de datos del XDR`;
  }
}
function fetchComputerData(filterParams) {
  console.log(`Búsqueda de datos para la entidad: ${filterParams.filterValue}`);

  let apiToken = CacheService.getScriptCache().get("apiToken");

  if (!apiToken) {
    console.error("Token no encontrado en caché. Inicializando nueva sesión...");
    const tokens = initializeAndMaintainSession();
    apiToken = tokens ? tokens[1] : null;
  }

  if (!apiToken) {
    console.error("No se pudo obtener un token válido. Abortando.");
    return null;
  }

  const apiUrl = "https://cloudinfra-gw-us.portal.checkpoint.com/app/endpoint-web-mgmt/harmony/endpoint/api/v1/asset-management/computers/filtered";

  const requestBody = {
    filters: [
      {
        columnName: filterParams.columnName,
        filterValues: [filterParams.filterValue],
        filterType: "Contains"
      }
    ],
    paging: {
      pageSize: 10,
      offset: 0
    },
    viewType: "DEVICES"
  };

  const options = {
    method: "post",
    contentType: "application/json",
    headers: {
      "Authorization": `Bearer ${getBearerToken()}`,
      "x-mgmt-api-token": apiToken,
      "x-mgmt-run-as-job": "on"
    },
    payload: JSON.stringify(requestBody),
    muteHttpExceptions: true
  };

  try {
    const response = UrlFetchApp.fetch(apiUrl, options);
    const responseCode = response.getResponseCode();
    const responseData = response.getContentText();

    console.log(`Código de respuesta: ${responseCode}`);
    console.log(`Datos de respuesta: ${responseData}`);

    if (responseCode === 200 || responseCode === 201) {
      const data = JSON.parse(responseData);
      if (data.jobId) {
        console.log("Job ID recibido:", data.jobId);

        const result = fetchJobResult(data.jobId, apiToken, "computer");

        if (result && result.computers) {
          console.log("Datos de computadoras obtenidos:", JSON.stringify(result.computers, null, 2));
          return result.computers; // Devuelve los datos de las computadoras
        } else {
          console.error("No se pudieron obtener datos de computadoras.");
          return null;
        }
      } else {
        console.error("No se recibió un jobId válido.");
        return null;
      }
    } else {
      console.error(`Error en la solicitud: ${responseData}`);
      return null;
    }
  } catch (error) {
    console.error(`Error al realizar la solicitud: ${error.message}`);
    return null;
  }
}function fetchJobResult(jobId, token, dataType) {
  const jobApiUrl = `https://cloudinfra-gw-us.portal.checkpoint.com/app/endpoint-web-mgmt/harmony/endpoint/api/v1/jobs/${jobId}`;
  
  const options = {
    method: "get",
    headers: {
      "Authorization": `Bearer ${getBearerToken()}`,
      "x-mgmt-api-token": token
    },
    muteHttpExceptions: true
  };

  let retries = 0;
  const maxRetries = 10; // máximo de 10 intentos

  try {
    while (retries < maxRetries) {
      const response = UrlFetchApp.fetch(jobApiUrl, options);
      const responseCode = response.getResponseCode();
      const responseData = response.getContentText();
      const jobStatus = JSON.parse(responseData);

      console.log(`Estado del job (${jobId}):`, jobStatus);

      if (responseCode === 200) {
        if (jobStatus.status === "DONE") {
          if (dataType === "computer") {
            return filterComputerData(jobStatus.data);
          }else {
            return jobStatus.data;
          }
        } else if (jobStatus.status === "FAILED") {
          console.error("El job falló. Detalles:", jobStatus);
          return null;
        }
      } else {
        console.error(`Error al consultar el estado del job: ${responseData}`);
        return null;
      }

      // Exponential backoff: espera más tiempo entre intentos
      const waitTime = Math.min(500 * Math.pow(2, retries), 5000); // 2^retries y max 5 segundos
      console.log(`Esperando ${waitTime / 1000} segundos antes del próximo intento...`);
      Utilities.sleep(waitTime);
      retries++;
    }

    console.error("Se alcanzó el máximo de intentos sin éxito.");
    return null;
  } catch (error) {
    console.error(`Error al consultar el estado del job: ${error.message}`);
    return null;
  }
}

function filterComputerData(data) {
  const filteredComputers = data.computers.map(computer => ({
    totalCount: data.totalCount,
    browserExtension: computer.browserExtension,
    threatEmulation: computer.threatEmulation,
    efr: computer.efr,
    antiBot: computer.antiBot,
    antiMalware: computer.antiMalware,
    daWinPatchInformation: computer.daWinPatchInformation,
    posture: computer.posture,
    fde: computer.fde,
    computerId: computer.computerId,
    computerName: computer.computerName,
    computerDeploymentStatus: computer.computerDeploymentStatus,
    computerIP: computer.computerIP,
    computerCapabilities: computer.computerCapabilities,
    computerClientVersion: computer.computerClientVersion,
    computerDeployTime: computer.computerDeployTime,
    computerLastErrorCode: computer.computerLastErrorCode,
    computerLastErrorDescription: computer.computerLastErrorDescription,
    computerGroups: computer.computerGroups,
    computerLastConnection: computer.computerLastConnection,
    computerSyncedon: computer.computerSyncedon,
    computerLastLoggedInUser:  computer.computerLastLoggedInUser ,
    computerUserName: computer.computerUserName,
    computerLastLoggedInPrebootUser: computer.computerLastLoggedInPrebootUser ,
    computerFdeStatus: computer.computerFdeStatus,
    computerFdeProgress: computer.computerFdeProgress,
    daInstalled: computer.daInstalled,
    computerType: computer.computerType,
    amUpdatedOn: computer.amUpdatedOn,
    osName: computer.osName,
    osVersion: computer.osVersion,
    isolationStatus: computer.isolationStatus,
    distinguishedName: computer.distinguishedName,
    isDeleted: computer.isDeleted,
    amStatus: computer.amStatus,
    complianceStatus: computer.complianceStatus,
    deviceComment: computer.deviceComment,
    extraCol1: computer.extraCol1,
    canonicalName: computer.canonicalName,
    deviceParents: computer.deviceParents,
    isInDomain: computer.isInDomain,
    domainName: computer.domainName,
    endpointType: computer.endpointType,
    scannerId: computer.scannerId,
    computerAmInfections: computer.computerAmInfections,
    computerNotRunningBladesMask: computer.computerNotRunningBladesMask,
    computerSdPackageName: computer.computerSdPackageName,
    computerSdPolicyName: computer.computerSdPolicyName,
    computerSdPolicyVersion: computer.computerSdPolicyVersion,
    computerAbState: computer.computerAbState,
    computerAbStatusBotNames: computer.computerAbStatusBotNames,
    computerAmScannedon: computer.computerAmScannedon,
    computerAmTotalQuarantined: computer.computerAmTotalQuarantined,
    computerLastContactedPolicyServerIp: computer.computerLastContactedPolicyServerIp,
    computerLastContactedPolicyServerName: computer.computerLastContactedPolicyServerName,
    computerSdPackageVersion: computer.computerSdPackageVersion,
    computerComplianceViolationIds: computer.computerComplianceViolationIds,
    computerStatusSummary: computer.computerStatusSummary,
    computerFdePrebootStatusUpdatedOn: computer.computerFdePrebootStatusUpdatedOn,
    computerSmartCardStatus: computer.computerSmartCardStatus,
    enforcedModifiedOn: computer.enforcedModifiedOn,
    deployedModifiedOn: computer.deployedModifiedOn,
    computerFdeWilWolStatus: computer.computerFdeWilWolStatus,
    computerFdeVersion: computer.computerFdeVersion,
    computerFdeWilWolStatusUpdatedOn: computer.computerFdeWilWolStatusUpdatedOn,
    computerFdeLastRecoveryDate: computer.computerFdeLastRecoveryDate,
    computerFdeTpmStatus: computer.computerFdeTpmStatus,
    computerFdeTpmVersion: computer.computerFdeTpmVersion,
    computerFdeTpmId: computer.computerFdeTpmId,
    enforcedNamePolicyMalware20: computer.enforcedNamePolicyMalware20,
    enforcedNamePolicyTe130: computer.enforcedNamePolicyTe130,
    enforcedNamePolicyEfr120: computer.enforcedNamePolicyEfr120,
    enforcedNamePolicyAntibot100: computer.enforcedNamePolicyAntibot100,
    enforcedNamePolicyMe30: computer.enforcedNamePolicyMe30,
    enforcedNamePolicyFdeDevice35: computer.enforcedNamePolicyFdeDevice35,
    enforcedNamePolicyFdeUser36: computer.enforcedNamePolicyFdeUser36,
    enforcedNamePolicyFw10: computer.enforcedNamePolicyFw10,
    enforcedNamePolicyCompliance60: computer.enforcedNamePolicyCompliance60,
    enforcedNamePolicyApplicationControl22: computer.enforcedNamePolicyApplicationControl22,
    enforcedNamePolicySaAccessZones11: computer.enforcedNamePolicySaAccessZones11,
    enforcedNamePolicyCommonClientSettings51: computer.enforcedNamePolicyCommonClientSettings51,
    enforcedNamePolicyDocSecPolicy91: computer.enforcedNamePolicyDocSecPolicy91,
    deployedNamePolicyMalware20: computer.deployedNamePolicyMalware20,
    deployedNamePolicyTe130: computer.deployedNamePolicyTe130,
    deployedNamePolicyEfr120: computer.deployedNamePolicyEfr120,
    deployedNamePolicyAntibot100: computer.deployedNamePolicyAntibot100,
    deployedNamePolicyMe30: computer.deployedNamePolicyMe30,
    deployedNamePolicyFdeDevice35: computer.deployedNamePolicyFdeDevice35,
    deployedNamePolicyFdeUser36: computer.deployedNamePolicyFdeUser36,
    deployedNamePolicyFw10: computer.deployedNamePolicyFw10,
    deployedNamePolicyCompliance60: computer.deployedNamePolicyCompliance60,
    deployedNamePolicyApplicationControl22: computer.deployedNamePolicyApplicationControl22,
    deployedNamePolicySaAccessZones11: computer.deployedNamePolicySaAccessZones11,
    deployedNamePolicyCommonClientSettings51: computer.deployedNamePolicyCommonClientSettings51,
    deployedNamePolicyDocSecPolicy91: computer.deployedNamePolicyDocSecPolicy91,
  }));

  return {
    totalCount: data.totalCount,
    computers: filteredComputers
  };
}function getIdVirtualGroup(term) {
  let token = CacheService.getScriptCache().get("apiToken");

  if (!token) {
    console.error("Token no encontrado en caché. Inicializando nueva sesión...");
    token = initializeAndMaintainSession();
  }

  if (!token) {
    console.error("No se pudo obtener un token válido.");
    return null;
  }

  console.log("Bearer Token utilizado para la solicitud:", token);

  const apiUrl = `https://cloudinfra-gw-us.portal.checkpoint.com/app/endpoint-web-mgmt/harmony/endpoint/api/v1/policy/metadata`;

  const options = {
    method: "get",
    contentType: "application/json",
    headers: {
      "Authorization": `Bearer ${bearerToken}`,
      "x-mgmt-api-token": token,
      "x-mgmt-run-as-job": "on",
    },
    muteHttpExceptions: true,
  };

  try {
    // Hacer la solicitud inicial para obtener el Job ID
    const response = UrlFetchApp.fetch(apiUrl, options);
    const responseCode = response.getResponseCode();
    const responseData = JSON.parse(response.getContentText());

    console.log(`Código de respuesta: ${responseCode}`);
    console.log(`Datos de respuesta: ${JSON.stringify(responseData)}`);

    if (responseCode === 200 || responseCode === 201) {
      if (responseData.jobId) {
        console.log("Job ID recibido:", responseData.jobId);

        // Obtener todos los resultados del Job (manejar paginación)
        const allResults = fetchJobResult(responseData.jobId, token);
        console.log("Numero de Politicas: ", allResults.length)
        if (allResults && Array.isArray(allResults)) {
          const termUpperCase = term.toUpperCase();

          // Filtrar los resultados basados en si contienen el término (insensible a mayúsculas/minúsculas)
          const filteredResults = allResults
            .filter((item) => item.name.toUpperCase().includes(termUpperCase))
            .map((item) => ({ id: item.id, name: item.name })); // Retornar solo id y name

          console.log("Resultados filtrados:", filteredResults);
          console.log("Total de resultados: ", filteredResults.length)
          return filteredResults;
        } else {
          console.error("El resultado del Job no contiene datos válidos.");
          return null;
        }
      } else {
        console.error("No se recibió un Job ID válido.");
        return null;
      }
    } else {
      console.error(`Error en la solicitud: ${responseData}`);
      return null;
    }
  } catch (error) {
    console.error(`Error al realizar la solicitud: ${error.message}`);
    return null;
  }
}

function getInfoPolicy() {
  let token = CacheService.getScriptCache().get("apiToken");

  if (!token) {
    console.error("Token no encontrado en caché. Inicializando nueva sesión...");
    token = initializeAndMaintainSession();
  }

  if (!token) {
    console.error("No se pudo obtener un token válido.");
    return null;
  }

  namePolicy = "Claro";
  getMetaData = getIdVirtualGroup(namePolicy);

  
  const ruleId = "0de95267-ab5d-4d64-8ffe-963bb7e18c25@40053f20-8bf0-4c6e-af0e-41d9e5df6993@759a4457-8e91-421b-9c1f-4c563303b96a@ecf2c156-e3a0-46df-a50a-5ba712648708";
  const apiUrl = `https://cloudinfra-gw.portal.checkpoint.com/app/endpoint-web-mgmt/harmony/endpoint/api/policy/threat-prevention/${ruleId}?detailsLevel=FULL`;

  const options = {
    method: "get",
    contentType: "application/json",
    headers: {
      "Authorization": `Bearer ${bearerToken}`,
      "accept": "application/json",
      "x-mgmt-api-token": token,
      "x-mgmt-run-as-job": "on",
    },
    muteHttpExceptions: true,
  };

  try {
    // Hacer la solicitud inicial para obtener el Job ID
    const response = UrlFetchApp.fetch(apiUrl, options);
    const responseCode = response.getResponseCode();
    const responseData = JSON.parse(response.getContentText());

    console.log(`Código de respuesta: ${responseCode}`);
    console.log(`Datos de respuesta: ${JSON.stringify(responseData)}`);

    if (responseCode === 200 || responseCode === 201) {
      if (responseData.jobId) {
        console.log("Job ID recibido:", responseData.jobId);

        // Obtener todos los resultados del Job (manejar paginación)
        const allResults = fetchJobResult(responseData.jobId, token);
        console.log("Numero de Politicas: ", allResults.length)
        saveLog(allResults, "Prueba obtencion thread prevention");
        return allResults
      } else {
        console.error("No se recibió un Job ID válido.");
        return null;
      }
    } else {
      console.error(`Error en la solicitud: ${responseData}`);
      return null;
    }
  } catch (error) {
    console.error(`Error al realizar la solicitud: ${error.message}`);
    return null;
  }
  }
  

WIT_AI_TOKEN = "HECKTT6CJGO4L3NO3JV2VF7NPGS6QH2C";

function onMessage(event) {
  let userInput = event.message?.text?.trim();
  userInput = userInput.replace(/@Asistente Seguridad\s*/g, '').trim();

  console.log("Mensaje recibido del usuario (sin mención):", userInput);
  console.log("Mensaje recibido del usuario:", userInput);
  const userName = formatName(event.user.displayName); 
  
 const witResponse = analyzeTextWithWitAi(userInput);
  console.log("Respuesta de Wit.ai:", witResponse);

  if (!witResponse) {
    console.error("Error: No se pudo analizar el mensaje con Wit.ai.");
    return {text:"No se pudo analizar tu mensaje. Inténtalo de nuevo."};
  }

  // Obtener intención y entidad
  const intent = getIntentFromWitResponse(witResponse);
  console.log("Intención detectada:", intent);

  const entity = getEntityFromWitResponse(witResponse);
  console.log("Entidad detectada:", entity);

  if (!intent) {
    console.warn("Advertencia: No se detectó intención en el mensaje.");
    return {text: "No entendí la intención de tu mensaje. ¿Puedes reformularlo?"};
  }

  if (!entity && intent != "home") {
    console.warn(`Advertencia: No se detectó una entidad válida. Intención: ${intent}`);
    return {text: `No encontré información suficiente para procesar tu solicitud.`};
  }

  let hostDataList;
  let filterParams;
  
  const otherFilter = ["home", "get_ioc", "get_logs"];

  if (!otherFilter.includes(intent)) {
    // Generar los parámetros para el filtrado dinámico
    const { entityName, entityValue } = entity;
    console.log("Generando parámetros para el filtrado:", entityName, entityValue);
    filterParams = generateFilterParams(entityName, entityValue);
    console.log("Parámetros generados:", filterParams);

    if (filterParams == "Na"){
      return {text: "Usuario no encontrado"}
    }
    if (!filterParams) {
    console.error(`Error: No se pudo manejar la entidad "${entityName}".`);
    return `No puedo manejar la entidad "${entityName}". Por favor, verifica tu entrada.`;
    }

    hostDataList = fetchComputerData(filterParams);
    console.log("Datos obtenidos:", hostDataList);

    if (!hostDataList) {
      console.error("Error: No se encontraron datos para los parámetros proporcionados.");
      return {text: "No se encontraron datos con los parámetros proporcionados."};
    }
  }

  // Manejo de la intención y creación de la plantilla de respuesta
  switch (intent) {
    case "computer_info":
      console.log("Procesando intención 'computer_info'");
       return {text:`Hola ${userName} ${computerInfoTemplate(hostDataList, entity.entityName)}`};

    case "report":
      console.log("Procesando intención 'report'");
      return {text:`Hola ${userName} ${reportTemplate(hostDataList, entity.entityName)}`};

    case "policy":
      console.log("Procesando intención 'policy'");
      return {text:`Hola ${userName} ${policyInfoTemplate(hostDataList, entity.entityName)}`};
      
    case "access_url":
      console.log("Procesando intención 'access_url'");
      return {text:`Hola ${userName} ${handleAccessUrl(witResponse, hostDataList)}`};

    case "home":
      console.log("Procesando intencion 'home'");
      return {text:`Hola ${userName} ${homeTemplate()}`}

    case "get_ioc":
      console.log("Procesando intencion 'get_ioc'");
      return {text: `Hola ${userName} ${handleAccessIoc(witResponse)}`}
    
    case "get_logs":
      console.log("Procesando intencion 'get_logs'");
      return {text: `Hola ${userName} ${handleAccessLogs(witResponse)}`}

    default:
      console.warn("Advertencia: Intención no manejada:", intent);
      return {text: "Lo siento, no puedo manejar esa solicitud aún."};
  }
}

// Conexión con Wit.ai
function analyzeTextWithWitAi(userInput) {
  const apiUrl = "https://api.wit.ai/message";
  const options = {
    method: "get",
    headers: {
      "Authorization": `Bearer ${WIT_AI_TOKEN}`,
    },
    muteHttpExceptions: true,
  };

  try {
    const query = encodeURIComponent(userInput);
    const response = UrlFetchApp.fetch(`${apiUrl}?q=${query}`, options);

    if (response.getResponseCode() === 200) {
      return JSON.parse(response.getContentText());
    } else {
      console.error("Error al conectar con Wit.ai:", response.getContentText());
      return null;
    }
  } catch (error) {
    console.error("Error al analizar texto con Wit.ai:", error.message);
    return null;
  }
}

// Extrae la intención principal de la respuesta de Wit.ai
function getIntentFromWitResponse(witResponse) {
  return witResponse.intents?.[0]?.name || null;
}

// Extrae la entidad principal de la respuesta de Wit.ai
function getEntityFromWitResponse(witResponse) {
  if (witResponse.entities) {
    const validEntities = ["host_name", "username", "name", "ioc", "fecha"];
    for (let key of Object.keys(witResponse.entities)) {
      // Extraer solo el tipo principal (antes de ':')
      const entityName = key.split(":")[0];
      if (validEntities.includes(entityName)) {
        let entityValue = witResponse.entities[key][0]?.value;
        entityValue = entityValue.replace(/^"(.*)"$/, "$1").trim();
        return { entityName, entityValue };
      }
    }
  }
  return null;
}


// Genera parámetros de filtrado dinámico basados en la entidad
function generateFilterParams(entityName, entityValue) {
  console.log("Procesando parámetros para la entidad:", entityName, entityValue);

  // Extraer el nombre de la entidad principal si viene en formato "tipo:subtipo"
  const mainEntity = entityName.split(":")[0];

  switch (mainEntity) {
    case "host_name":
      return {
        columnName: "computerName",
        filterValue: entityValue
      };

    case "username":
      let name = searchComputersByUserId(entityValue);
      if (name == null){
        return "Na";
      }
      return {
        columnName: "computerLastLoggedInUser",
        filterValue: name
      };

    case "name":
      return {
        columnName: "computerLastLoggedInUser",
        filterValue: entityValue
      };

    default:
      console.warn("Entidad no reconocida:", mainEntity);
      return null;
  }
}

// Funcion para obtener info de un equipo en harmony
function computerInfoTemplate(hostDataList, entityName) {
   if (!hostDataList || hostDataList.length === 0) {
      if (entityName == "host_name"){
          return "el equipo no reporta en la consola de Harmony.";
      }
      return "el usuario no reporta en la consola de Harmony."
  }
  let responseList = `se encontraron ${hostDataList.length} resultados:\n`;

  hostDataList.forEach((hostData, index) => {
    responseList += `
*${index + 1}. Hostname:* ${hostData.computerName || "N/A"}
   - _Ip:_ ${hostData.computerIP}
   - _Tipo:_ ${hostData.computerType}
   - _Política:_ ${hostData.computerGroups[0]?.name || "No asignada"}
   - _Sistema operativo:_ ${hostData.osName || "N/A"} (${hostData.osVersion || "N/A"})
   - _Usuario conectado:_ ${hostData.computerLastLoggedInUser || "N/A"} - ${hostData.computerUserName || "N/A"}
   - _Última conexión:_ ${formatTimestamp(hostData.computerLastConnection || "Sin conexión registrada")}
    `;
  });

  return responseList;
}

// Funcion para verificar si el equipo reporta en harmony
function reportTemplate(hostDataList, entityName) {
  if (!hostDataList || hostDataList.length === 0) {
      if (entityName == "host_name"){
          return "el equipo no reporta en la consola de Harmony.";
      }
      return "el usuario no reporta en la consola de Harmony."
  }
  return `el equipo reporta en la consola de Harmony:\n` +
    hostDataList.map((hostData, index) => {
      const lastConnection = hostData.computerLastConnection 
        ? formatTimestamp(hostData.computerLastConnection)
        : "Sin conexión registrada";
      const computerName = hostData.computerName || "Nombre no disponible";
      const policy = (hostData.computerGroups && hostData.computerGroups[0]?.name) || "Política no asignada";
      const lastUser = hostData.computerLastLoggedInUser || "Usuario no disponible";
      const userName = hostData.computerUserName || "N/A";
      return `*${index + 1}. Equipo:* ${computerName}
   - _Última conexión:_ ${lastConnection}
   - _Política:_ ${policy}
   - _Usuario:_ ${lastUser} - ${userName}`;
    }).join("\n");
}


// Funcion para obtener la informacion sobre una politica
function policyInfoTemplate (hostDataList, entityName) { 
   if (!hostDataList || hostDataList.length === 0) {
      if (entityName == "host_name"){
          return "el equipo no reporta en la consola de Harmony.";
      }
      return "el usuario no reporta en la consola de Harmony."
  }
  let responseList = `esta es la informacion de las politicas instaladas:\n`;

  hostDataList.forEach((hostData, index) => {
    responseList += `
*${index + 1}. Hostname:* ${hostData.computerName || "N/A"}
   - _Grupo:_  ${hostData.computerGroups[0]?.name || "N/A"}
   - _Cliente comun:_ ${hostData.deployedNamePolicyCommonClientSettings51 || "N/A"}
   - _Anti-malware:_ ${hostData.deployedNamePolicyMalware20 || "N/A"}
   - _Antibot:_ ${hostData.deployedNamePolicyAntibot100 || "N/A"} 
   - _Antiransomware:_ ${hostData.deployedNamePolicyEfr120 || "N/A"}
   - _Cumplimiento:_ ${hostData.deployedNamePolicyCompliance60 || "N/A"}
   - _Cifrado de medios:_ ${hostData.deployedNamePolicyMe30 || "N/A"}
   - _Firewall:_ ${hostData.deployedNamePolicyFw10 || "N/A"}
   - _Definicion de zona:_ ${hostData.deployedNamePolicySaAccessZones11 || "N/A"}
   - _Application Control:_ ${hostData.deployedNamePolicyApplicationControl22 || "N/A"}
   - _Full Disk Encryption:_ ${(hostData.deployedNamePolicyFdeUser36 == "999"? "Default": hostData.deployedNamePolicyFdeUser36) || "N/A"}
    `;
  });

  return responseList;
}

// Funcion para informar de los requisitos de salida a Home
function homeTemplate() {
  const response = `eso ya deberias saberlo, aqui tienes la información para sacar un equipo a home. Asegúrate de tener en cuenta lo siguiente:

  _Requisitos previos:_
  - Nombre completo del equipo
  - Datos del colaborador
  - Campaña correspondiente

Una vez que tengas esta información, deberás crear un caso en GLPI dirigido al equipo de Seguridad de la Información, cumpliendo con la siguiente plantilla para su aprobación:

  1. *Instalación de Veracrypt*: Verifica que el disco esté cifrado y que el nombre completo del equipo esté visible.
  2. *Colector de Eventos*: Asegúrate de que Win Collect esté instalado y que el nombre completo del equipo esté visible.
  3. *Checkpoint (Harmony)*: Confirma que Harmony esté protegido y que el nombre completo del equipo esté visible.
  4. *GoTeam (Giitic)*: Verifica que esté instalado y configurado, y que el nombre completo del equipo esté visible.
  5. *Bloqueo de BIOS*: Confirma que se haya realizado el bloqueo.
  6. *Licencia de AnyDesk*: Asegúrate de que esté instalado y configurado, y que el nombre completo del equipo esté visible.

_Si el equipo es de PCI - Mercado Libre, adicionalmente:_
  7. *DLP*: Verifica que esté instalado y configurado, y que el nombre completo del equipo esté visible.

Una vez que todo esté en orden, podrás avanzar con la salida del equipo a home. No olvides reportar a inventarios y entregar los documentos al colaborador, asegurándote de que firme las actas.
  `;
  
  return response;
}
function iocInfoTemplate(iocDataList) {
let responseList = `el indicador se encuentra en el Ioc de XDR:\n`;

  iocDataList.forEach((iocData, index) => {
    responseList += `
*${index + 1}. Indicador:* ${iocData.indicator_value || "N/A"}
  - _Severidad:_ ${formatSeverity(iocData.severity) || "N/A"}
  - _Confianza:_ ${formatSeverity(iocData.confidence) || "N/A"}
  - _Descripción:_ ${iocData.description || "N/A"}
  - _Fecha de creación:_ ${formatIso(iocData.creation_date) || "N/A"}
  - _Fecha de expiracion:_ ${formatIso(iocData.ttl) || "N/A"}
  - _Estado:_ ${iocData.enabled ? "Activo" : "Desactivado"},
  - _Última actualización:_ ${formatIso(iocData.last_update) || "N/A"}
    `;
  });

  return responseList;
}
// Función para formatear un timestamp a fecha y hora legibles
function formatTimestamp(timestamp) {
  const date = new Date(parseInt(timestamp, 10)); // Asegurarse de que sea un número
  const options = {
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  };
  return date.toLocaleString("es-ES", options);
}

// Formatea de ISO a Fecha y hora legibles
function formatIso(isoDate) {
  if (!isoDate) return "Fecha no disponible";

  const date = new Date(isoDate);
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  const hours = String(date.getHours()).padStart(2, "0");
  const minutes = String(date.getMinutes()).padStart(2, "0");

  return `${year}-${month}-${day} ${hours}:${minutes}`;
}

// Funcion para formatar la fecha
function formatDate(dateString) {
  return dateString ? new Date(dateString).toISOString() : "Desconocida";
}

// Funcion para formatear la hora
function formatTime(date) {
  return date.toISOString().split("T")[1].split(".")[0];
}

//Funcion para obtener primer nombre y apellido
function formatName(nombreCompleto) {
    const nombres = nombreCompleto.split(' '); 
    const primerNombre = nombres[0]; 
    const apellido = nombres[nombres.length - 2]; 
    return `${primerNombre} ${apellido}`; 
}

// Funcion para transformar numeros en texto legible
function formatSeverity(severity) {
  if (severity <= 33) return "Baja";
  if (severity <= 66) return "Media";
  return "Alta";
}

//Funcion para obtener el nombre de usuario por cedula o usuario registrado en caso de claro
function searchComputersByUserId(userId) {
  let apiToken = CacheService.getScriptCache().get("apiToken");

  if (!apiToken) {
    console.error("Token no encontrado en caché. Inicializando nueva sesión...");
    const tokens = initializeAndMaintainSession();
    apiToken = tokens ? tokens[1] : null;
  }

  if (!apiToken) {
    console.error("No se pudo obtener un token válido. Abortando.");
    return null;
  }

  const url = "https://cloudinfra-gw.portal.checkpoint.com/app/endpoint-web-mgmt/harmony/endpoint/api/v1/organization/tree/search"; // URL de la API

  const data = {
    "searchTerm": userId, 
    "searchType": "CONTAINS", 
    "paging": {
      "pageSize": 10, 
      "offset": 0
    },
    "entityTypesToSearch": ["USER", "COMPUTER", "VIRTUAL_GROUP"] 
  };

  const options = {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${getBearerToken()}`,
      "x-mgmt-api-token": apiToken,
      "x-mgmt-run-as-job": "on"  
    },
    payload: JSON.stringify(data)
  };

  const response = UrlFetchApp.fetch(url, options);
  const responseData = JSON.parse(response.getContentText());

  const result = fetchJobResult(responseData.jobId, apiToken); 
 if (response.getResponseCode() === 200) {
    console.log("Computadoras asociadas al usuario:", result);
    
    if (result && result.length > 0) {
      return result[0].name ? result[0].name : null; 
    } else {
      console.warn("No se encontraron computadoras asociadas al usuario.");
      return null; 
    }
  } else {
    console.log("Error al buscar computadoras:", result);
    return null;
  }
}

function prueba(){
  searchComputersByUserId("");
}

function checkSheetsForPolicy(policyName, urlKeyword) {
  const sheetId = "1RtFvo45emjkRXpC0GodTAaA_ycgFJdLEWAdywr94FbU";  
  const sheet = SpreadsheetApp.openById(sheetId);
  const sheets = sheet.getSheets();
  let policyFound = false;  

  const cleanedPolicy = cleanPolicyName(policyName);
  const cleanedUrlKeyword = cleanPolicyName(urlKeyword).replace(/['"]/g, "");;

  console.log(`Buscando política: ${cleanedPolicy}`);
  console.log(`Buscando URL: ${cleanedUrlKeyword}`);

  // Recorremos todas las hojas
  for (const sheet of sheets) {
    console.log(`Buscando en la hoja: ${sheet.getName()}`);

    // Verificar que la hoja tiene columnas antes de intentar buscar
    const lastColumn = sheet.getLastColumn();
    if (lastColumn < 1) {
      console.log(`⚠️ La hoja "${sheet.getName()}" no tiene columnas para buscar.`);
      continue;
    }

    // Encontrar la columna de la política
    const policyIndex = findPolicyColumn(sheet, cleanedPolicy);
    
    // Si no se encuentra la política en esta hoja, continuamos con la siguiente
    if (policyIndex === -1) {
      console.log(`❌ No se encontró la política "${policyName}" en ${sheet.getName()}.`);
      continue;
    }

    policyFound = true; // Marca que la política fue encontrada
    console.log(`Política encontrada en la columna ${policyIndex + 1} de la hoja ${sheet.getName()}`);

    // Obtener las URLs de la columna, desde la fila 3 en adelante
    const lastRow = sheet.getLastRow();
    if (lastRow < 3) {
      console.log(`⚠️ La hoja "${sheet.getName()}" no tiene suficientes filas para buscar URLs.`);
      continue;
    }

    const urlsColumn = sheet.getRange(3, policyIndex + 1, lastRow - 2).getValues().flat().map(url => url.toString().replace(/"/g, "").toUpperCase());  // Eliminar comillas dobles y convertir a mayúsculas

    // Verificar si alguna URL contiene el término `urlKeyword`
    const found = urlsColumn.some(url => url && url.includes(cleanedUrlKeyword.toUpperCase()));

    if (found) {
      console.log(`URL "${urlKeyword}" encontrada para la política "${policyName}".`);
      return true; 
    } else {
      console.log(`URL "${urlKeyword}" NO encontrada en la política "${policyName}" en la hoja ${sheet.getName()}.`);
      return false;
    }
  }

  // Si no se encuentra la política en ninguna hoja
  if (!policyFound) {
    console.log(`❌ No se encontró la política "${policyName}" en la matriz de roles y perfiles.`);
    return null; 
  }

  return false; // Si la URL no se encuentra en ninguna hoja
}

function cleanPolicyName(name) {
  return name.replace(/\b(politica|pol|v\d+|med|bog)\b/gi, "").replace(/\s+/g, ' ').trim().toUpperCase();
}

function findPolicyColumn(sheet, cleanedPolicy) {
  const policyRow = sheet.getRange(2, 1, 1, sheet.getLastColumn()).getValues()[0]; // Obtener la fila 2 de la hoja
  if (!policyRow || policyRow.length === 0) {
    console.log(`⚠️ La fila de encabezados está vacía o no tiene columnas en la hoja "${sheet.getName()}"`);
    return -1;  // Si la fila de encabezados está vacía, no continuamos
  }

  let bestMatchIndex = -1;

  // Recorremos las celdas de la fila 2 para encontrar la política
  policyRow.forEach((cell, index) => {
    if (!cell) return;

    const cellText = cell.toString().trim().toUpperCase();  // Convertir a mayúsculas para comparación insensible a mayúsculas

    // Comparar la política limpia con la celda
    if (cellText.includes(cleanedPolicy)) {
      bestMatchIndex = index;  // Guardar el índice si hay una coincidencia
    }
  });

  return bestMatchIndex;
}

function pageAccessTemplate(hostDataList, urlKeyword) {
  if (!hostDataList || hostDataList.length === 0) {
    return { text: "No se encontraron datos del equipo." };
  }

  const hostData = hostDataList[0]; // Tomamos el primer resultado
  const policyName = hostData.computerGroups[0]?.name || "Política no asignada";

  if (!policyName || policyName === "Política no asignada") {
    return "No se pudo determinar la política del equipo.";
  }

  console.log(`Buscando acceso para la política: ${policyName}, palabra clave: ${urlKeyword}`);

  // Buscar en Google Sheets si la política permite el acceso
  const hasAccess = checkSheetsForPolicy(policyName, urlKeyword);

  if (hasAccess) {
    return  `✅ Sí, el equipo con política *${policyName}* tiene permitido el acceso a *${urlKeyword}*.` ;
  } else {
    return `❌ No, el equipo con política *${policyName}* no tiene permitido el acceso a *${urlKeyword}*.`;
  }
}

function handleAccessUrl(witResponse, hostDataList) {
  let urlKeyword = null;

  // Buscar la entidad 'page'
  for (let key of Object.keys(witResponse.entities)) {
    if (key.startsWith("page")) {
      urlKeyword = witResponse.entities[key][0]?.value;
      break;
    }
  }

  if (!urlKeyword) {
    return "No especificaste una página web para verificar el acceso.";
  }

  const policyName = hostDataList[0]?.computerGroups[0]?.name || "Política desconocida";

  console.log(`Verificando acceso a la URL: ${urlKeyword} en la política: ${policyName}`);

  const accessCheck = checkSheetsForPolicy(policyName, urlKeyword);

    if (accessCheck === true) {
    return `✅ Sí, la política *${policyName}* permite el acceso a *${urlKeyword.replace(/['"]/g, "")}*.`
    ;
  } else if (accessCheck === null) {
    return `❌ No se encontró la política *${policyName}* en la matriz de roles y perfiles.`
    ;
  } else {
    return `❌ No, la política *${policyName}* no permite el acceso a *${urlKeyword.replace(/['"]/g, "")}*.`
    ;
  }
}

// Exclusioens de alertas
function getExcludedSources() {
  try {
    const sheetId = SpreadsheetApp.openById("1Q1QNSrgRIwQVSHmuoSfsMbZFxn9OLHe7NDI-xEXuky8");
    sheet = sheetId.getSheetByName("Exclusiones")
    if (!sheet) {
      console.error("❌ No se encontró la hoja 'Exclusiones'.");
      return [];
    }

    const data = sheet.getRange("A2:A").getValues().flat().filter(value => value.trim() !== "");
    console.log(`📌 Fuentes excluidas: ${JSON.stringify(data)}`);
    return data;
  } catch (error) {
    console.error("❌ Error al obtener exclusiones:", error.message);
    return [];
  }
}

// Guardado de logs en Google Sheets
function saveLogsToSheet(logs) {
  try {
    // Abrir la hoja de cálculo y la hoja "Logs"
    const spreadsheet = SpreadsheetApp.openById("1Q1QNSrgRIwQVSHmuoSfsMbZFxn9OLHe7NDI-xEXuky8");
    const sheet = spreadsheet.getSheetByName("Logs");

    // Verificar si la hoja existe
    if (!sheet) {
      console.error("❌ No se encontró la hoja 'Logs'.");
      return;
    }

    // Preparar los datos para insertar
    const data = logs.map(log => {
      const source = log.resource?.[0] || log.file_name?.[0] || "N/A";
      let policy = log.policy_name.replace(/\s*\(.*\)$/, '').trim();
      const hash = log.file_sha1 || log.file_md5 || "N/A";
      return [
        formatIso(log.time), // Fecha y hora
        log.event_type || "N/A",          // Tipo de Evento
        log.protection_type || "N/A",     // Tipo de Protección
        log.severity || "N/A",
        log.action || "N/A",            // Severidad
        log.src_machine_name ? log.src_machine_name.replace(/.bop.local\s*/g, '') : "N/A", // Equipo
        log.src || "N/A",
        policy || "N/A",
        log.src_user_name[0],                             // Usuario
        log.description || "N/A",         // Descripción
        source,              // Fuente
        hash                 // Hash
      ];
    });

    // Si hay datos para insertar
    if (data.length > 0) {
      const lastRow = sheet.getLastRow(); // Obtener última fila con datos
      const newRow = lastRow + 1; // Definir la fila donde se insertarán los nuevos datos

      // Insertar los datos en la hoja
      sheet.getRange(newRow, 1, data.length, data[0].length).setValues(data);

      // Aplicar bordes a las nuevas filas
      const range = sheet.getRange(newRow, 1, data.length, data[0].length);
      range.setBorder(true, true, true, true, true, true);

      console.log(`✅ Se guardaron ${data.length} logs en la hoja 'Logs'.`);
    } else {
      console.log("📭 No hay logs para guardar.");
    }

  } catch (error) {
    console.error("❌ Error al guardar logs en la hoja:", error.message);
  }
}

function generateGraphic() {
  const spreadsheet = SpreadsheetApp.openById("1Q1QNSrgRIwQVSHmuoSfsMbZFxn9OLHe7NDI-xEXuky8");
  const sheet = spreadsheet.getSheetByName("Logs");
  if (!sheet) return;

  // Crear hoja auxiliar para resúmenes
  let summarySheet = spreadsheet.getSheetByName("Resumen");
  if (!summarySheet) {
    summarySheet = spreadsheet.insertSheet("Resumen");
  } else {
    summarySheet.clear(); // Limpiar datos
    summarySheet.getCharts().forEach(chart => summarySheet.removeChart(chart)); // Eliminar gráficos existentes
  }

  // 🔹 Agregar título general
  summarySheet.getRange("A1:E1").merge();
  summarySheet.getRange("A1").setValue("📊 Resumen de Logs").setFontSize(14).setFontWeight("bold").setHorizontalAlignment("center").setBackground("#D9E1F2");

  // 🔹 Encabezados
  const headers = [["Severidad", "Cantidad"], ["Tipo Evento", "Cantidad"]];
  const headerRange1 = summarySheet.getRange("A2:B2").setValues([headers[0]]);
  const headerRange2 = summarySheet.getRange("D2:E2").setValues([headers[1]]);

  // 🔹 Aplicar formato a los encabezados
  headerRange1.setBackground("#F4B400").setFontWeight("bold").setHorizontalAlignment("center").setFontColor("black");
  headerRange2.setBackground("#0F9D58").setFontWeight("bold").setHorizontalAlignment("center").setFontColor("white");

  // 🔹 Obtener datos
  const severityData = sheet.getRange("D2:D" + sheet.getLastRow()).getValues();
  const eventTypeData = sheet.getRange("B2:B" + sheet.getLastRow()).getValues();

  // 🔹 Contar ocurrencias
  let severityCounts = countOcurrency(severityData);
  let eventCounts = countOcurrency(eventTypeData);

  // Ordenar de mayor a menor
  severityCounts.sort((a, b) => b[1] - a[1]);
  eventCounts.sort((a, b) => b[1] - a[1]);

  // 🔹 Insertar datos
  const severityDataRange = summarySheet.getRange(3, 1, severityCounts.length, 2);
  const eventDataRange = summarySheet.getRange(3, 4, eventCounts.length, 2);
  
  severityDataRange.setValues(severityCounts);
  eventDataRange.setValues(eventCounts);

  // 🔹 Aplicar formato a los datos
  formatSummarySheet(summarySheet, severityDataRange, eventDataRange);

  // 🔹 Crear gráficos
  const chartSeveridad = summarySheet.newChart()
    .setChartType(Charts.ChartType.PIE)
    .addRange(summarySheet.getRange("A2:B" + (severityCounts.length + 2)))
    .setPosition(1, 8, 0, 0) // Cambiado a fila 3
    .setOption("title", "📌 Distribución de Severidad")
    .setOption("legend", { position: "right" })
    .setOption("pieHole", 0.4) // Gráfico de dona
    .setOption("pieSliceText", "percentage") // Mostrar porcentaje en el gráfico circular
    .build();

  // Verificar que haya datos antes de crear el gráfico de tipo de evento
  if (eventCounts.length > 0) {
    const chartTipo = summarySheet.newChart()
      .setChartType(Charts.ChartType.COLUMN)
      .addRange(summarySheet.getRange(3, 4, eventCounts.length, 2)) 
      .setPosition(18, 8, 0, 0) 
      .setOption("title", "📊 Eventos por Tipo")
      .setOption("hAxis", { title: "Tipo de Evento" })
      .setOption("vAxis", { title: "Cantidad" })
      .setOption("colors", ["#4285F4"]) // Azul de Google
      .setOption("annotations", { textStyle: { color: '#000', fontSize: 12 } }) 
      .build();

    summarySheet.insertChart(chartTipo);
  }
  summarySheet.insertChart(chartSeveridad);
}

// 🔹 Función para contar ocurrencias en los datos
function countOcurrency(data) {
  const counts = {};
  data.forEach(row => {
    const key = row[0] || "N/A";
    counts[key] = (counts[key] || 0) + 1;
  });
  return Object.entries(counts).map(([key, value]) => [key, value]);
}

// 🔹 Función para aplicar formato a la hoja de resumen
function formatSummarySheet(sheet, severityRange, eventRange) {
  // Aplicar bordes y autoajuste a los datos
  if (severityRange.getNumRows() > 0) {
    severityRange.setBorder(true, true, true, true, false, false).setHorizontalAlignment("center");
  }
  if (eventRange.getNumRows() > 0) {
    eventRange.setBorder(true, true, true, true, false, false).setHorizontalAlignment("center");
  }

  // Autoajustar columnas
  sheet.autoResizeColumns(1, 5);
}
function checkVirusTotal(source, hash) {
  let sheet = SpreadsheetApp.openById("1Q1QNSrgRIwQVSHmuoSfsMbZFxn9OLHe7NDI-xEXuky8").getSheetByName("Virustotal");
  let data = sheet.getDataRange().getValues();

  // **🔎 Buscar primero por fuente**
  let result = data.find(row => row[0] === source);
  if (!result && hash) {
    // **🔎 Si no está la fuente, buscar por hash**
    result = data.find(row => row[1] === hash);
  }

  if (result) {
    console.log("🔍 Encontrado en Google Sheets");
    return {
      detections: result[2],
      verdict: result[3],
      url: result[4]
    };
  }

  console.log("🔎 No encontrado en Google Sheets, consultando VirusTotal...");
  let apiResponse = hash ? queryVirusTotal(hash) : queryVirusTotal(source);

  if (apiResponse) {
    console.log("📥 Guardando nuevo registro en Google Sheets...");
    sheet.appendRow([source, hash || "N/A", apiResponse.detections, apiResponse.verdict, apiResponse.url]);

    // **🖼️ Aplicar bordes a toda la tabla**
    let lastRow = sheet.getLastRow();
    let lastColumn = sheet.getLastColumn();
    let range = sheet.getRange(1, 1, lastRow, lastColumn);
    range.setBorder(true, true, true, true, true, true);

    return apiResponse;
  }

  return null;
}

// **🔬 Consultar la API de VirusTotal**
function queryVirusTotal(query) {
  let apiKey = "205f53117065d34d6bc9ff63b3a8d5014f7e2047ce94ded6c6abb73b4a701879";
  let isHash = /^[a-fA-F0-9]{32,64}$/.test(query);  // Detectar si es un hash (MD5, SHA-1 o SHA-256)
  let isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(query); // Detectar si es una IP
  let isURL = query.includes(".") && !isIP;         // Detectar si es una URL/Dominio

  let endpoint = isHash ? `files/${query}` 
                : isIP ? `ip_addresses/${query}` 
                : isURL ? `domains/${query}` 
                : null;

  if (!endpoint) {
    console.error("❌ Error: No se pudo determinar el tipo de consulta.");
    return null;
  }

  let url = `https://www.virustotal.com/api/v3/${endpoint}`;
  let options = {
    method: "get",
    headers: { "x-apikey": apiKey },
    muteHttpExceptions: true
  };

  try {
    let response = UrlFetchApp.fetch(url, options);
    let result = JSON.parse(response.getContentText());
    
    // Mostrar la respuesta para verificar qué devuelve la API
    console.log("Respuesta de VirusTotal:", result);

    if (result.data) {
      let analysis = result.data.attributes;
      let detections = `Malicioso: ${analysis.last_analysis_stats.malicious} | Sospechoso: ${analysis.last_analysis_stats.suspicious}`;
      let verdict;
      
      if (analysis.last_analysis_stats.malicious > 4){
        verdict = "⚠️ Malicioso";
      }else if(analysis.last_analysis_stats.malicious > 2 || analysis.last_analysis_stats.suspicious > 2){
        verdict = "⚠️ Malicioso/Sospechoso";
      }else if (analysis.last_analysis_stats.malicious > 0 || analysis.last_analysis_stats.suspicious > 0){
        verdict = "⚠️ Sospechoso";
      }else{
        verdict = "✅ Seguro";
      }

      // Generar URL del reporte en VirusTotal
      let reportUrl = `https://www.virustotal.com/gui/file/${result.data.id}`;

      return {
        detections: detections,
        verdict: verdict,
        url: reportUrl
      };
    } else {
      console.error("❌ No se encontró 'data' en la respuesta de la API de VirusTotal.");
    }
  } catch (error) {
    console.error("❌ Error en la consulta a VirusTotal:", error.message);
  }

  return null;
}

function prueba(){
  let result = checkVirusTotal("c:\windows\system32\sppextcomobjhook.dll","94ee8c5856dc0570a8f12cd08ecb0560f3a61908");
  console.log(result); 
}



  
