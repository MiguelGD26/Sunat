package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
)

func convertirHandler(w http.ResponseWriter, r *http.Request) {
	correlationID := uuid.New().String()
	log.Printf("[%s] Petición de conversión y envío recibida", correlationID)
	if r.Method != http.MethodPost {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}

	var docIn DocumentoElectronico
	if err := json.NewDecoder(r.Body).Decode(&docIn); err != nil {
		log.Printf("[%s] Error decodificando JSON: %v", correlationID, err)
		responderError(w, correlationID, "ERR_JSON_INVALIDO", "El cuerpo de la petición no es un JSON válido.", http.StatusBadRequest)
		return
	}

	xmlFirmado, err := ProcesarDocumento(&docIn)
	if err != nil {
		log.Printf("[%s] Error procesando documento: %v", correlationID, err)
		responderError(w, correlationID, "ERR_PROCESAMIENTO", err.Error(), http.StatusInternalServerError)
		return
	}

	nombreBase := fmt.Sprintf("%s-%s-%s-%s", docIn.Emisor.RUC, docIn.TipoDocumento, docIn.Serie, docIn.Correlativo)

	// Creamos los nombres completos para XML y ZIP
	nombreArchivoXML := nombreBase + ".xml"
	nombreArchivoZIP := nombreBase + ".zip"

	rutaArchivo := fmt.Sprintf("./storage/%s", nombreArchivoXML)
	if err := os.WriteFile(rutaArchivo, xmlFirmado, 0644); err != nil {
		log.Printf("[%s] Error guardando archivo XML local: %v", correlationID, err)
	} else {
		log.Printf("[%s] Archivo XML local guardado en %s", correlationID, rutaArchivo)
	}

	log.Printf("[%s] Intentando enviar documento a SUNAT...", correlationID)
	cdr, err := EnviarFacturaSUNAT(nombreArchivoZIP, nombreArchivoXML, xmlFirmado, docIn.Emisor.RUC)
	if err != nil {
		log.Printf("[%s] Error en el envío a SUNAT: %v", correlationID, err)
		responderError(w, correlationID, "ERR_ENVIO_SUNAT", err.Error(), http.StatusBadGateway)
		return
	}
	log.Printf("[%s] Documento enviado exitosamente a SUNAT. CDR recibido.", correlationID)

	respuesta := RespuestaExito{Status: "success", CorrelationId: correlationID, DocumentId: fmt.Sprintf("%s-%s", docIn.Serie, docIn.Correlativo), XmlPath: rutaArchivo, XmlHash: "sha256:" + calcularHash(xmlFirmado), ProcessedAt: time.Now().UTC().Format(time.RFC3339), SunatCDR: cdr}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(respuesta)
}

func responderError(w http.ResponseWriter, corrID, errCode, errMsg string, httpStatus int) {
	respuesta := RespuestaError{Status: "error", CorrelationId: corrID, ErrorCode: errCode, ErrorMessage: errMsg}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	json.NewEncoder(w).Encode(respuesta)
}
