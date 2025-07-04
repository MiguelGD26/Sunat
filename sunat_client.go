package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/beevik/etree"
)

// Client encapsula la configuración y la lógica para comunicarse con SUNAT.
type Client struct {
	httpClient *http.Client
	URL        string
	Username   string
	Password   string
}

// NewClient crea una nueva instancia del cliente de SUNAT.
// Las credenciales se configuran una sola vez aquí.
func NewClient(ruc, userSOL, passSOL string) *Client {
	// Para el billService en beta, la contraseña es el RUC.
	password := ruc

	return &Client{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		URL:        "https://e-beta.sunat.gob.pe/ol-ti-itcpfegem-beta/billService",
		Username:   ruc + userSOL,
		Password:   password,
	}
}

// EnviarFactura toma los datos del documento y realiza todo el proceso.
func (c *Client) EnviarFactura(nombreArchivoZIP, nombreArchivoXML string, xmlFirmado []byte) (string, error) {
	// 1. Crear el ZIP
	zipData, err := crearZip(nombreArchivoXML, xmlFirmado)
	if err != nil {
		return "", fmt.Errorf("error al crear el archivo ZIP: %w", err)
	}

	// 2. Construir el sobre SOAP con las credenciales del cliente
	soapRequest := construirSOAPRequest(nombreArchivoZIP, zipData, c.Username, c.Password)

	// 3. Realizar la petición HTTP
	req, err := http.NewRequest("POST", c.URL, bytes.NewBuffer(soapRequest))
	if err != nil {
		return "", fmt.Errorf("error al crear la petición HTTP: %w", err)
	}
	req.Header.Set("Content-Type", "text/xml;charset=UTF-8")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error al enviar la petición a SUNAT: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error al leer la respuesta de SUNAT: %w", err)
	}

	// 4. Procesar la respuesta
	if resp.StatusCode != http.StatusOK {
		if strings.Contains(string(respBody), "faultcode") {
			return "", fmt.Errorf("SUNAT respondió con un error SOAP: %s", respBody)
		}
		return "", fmt.Errorf("SUNAT respondió con estado HTTP %d: %s", resp.StatusCode, respBody)
	}

	return procesarRespuestaSUNAT(respBody)
}

// --- Funciones de Ayuda (Helpers) ---

func crearZip(nombreArchivo string, xmlData []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)
	zipFile, err := zipWriter.Create(nombreArchivo)
	if err != nil {
		return nil, err
	}
	if _, err := zipFile.Write(xmlData); err != nil {
		return nil, err
	}
	if err := zipWriter.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func construirSOAPRequest(nombreZip string, zipData []byte, usuario, password string) []byte {
	soapTemplate := `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ser="http://service.sunat.gob.pe" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><soapenv:Header><wsse:Security><wsse:UsernameToken><wsse:Username>%s</wsse:Username><wsse:Password>%s</wsse:Password></wsse:UsernameToken></wsse:Security></soapenv:Header><soapenv:Body><ser:sendBill><fileName>%s</fileName><contentFile>%s</contentFile></ser:sendBill></soapenv:Body></soapenv:Envelope>`
	zipBase64 := base64.StdEncoding.EncodeToString(zipData)
	return []byte(fmt.Sprintf(soapTemplate, usuario, password, nombreZip, zipBase64))
}

func procesarRespuestaSUNAT(soapResponse []byte) (string, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(soapResponse); err != nil {
		return "", fmt.Errorf("XML de respuesta SOAP mal formado: %w", err)
	}

	if fault := doc.FindElement("//faultstring"); fault != nil {
		return "", fmt.Errorf("SUNAT respondió con un error SOAP: %s", fault.Text())
	}

	cdrNode := doc.FindElement("//applicationResponse")
	if cdrNode == nil {
		return "", fmt.Errorf("no se encontró el nodo <applicationResponse> en la respuesta. Respuesta completa: %s", string(soapResponse))
	}

	// El CDR está en Base64, lo decodificamos
	cdrZipBytes, err := base64.StdEncoding.DecodeString(cdrNode.Text())
	if err != nil {
		return "", fmt.Errorf("no se pudo decodificar el CDR en Base64: %w", err)
	}

	// El CDR es un ZIP, lo leemos
	zipReader, err := zip.NewReader(bytes.NewReader(cdrZipBytes), int64(len(cdrZipBytes)))
	if err != nil {
		return "", fmt.Errorf("no se pudo leer el ZIP del CDR: %w", err)
	}

	// Buscamos el archivo XML dentro del ZIP
	for _, file := range zipReader.File {
		if strings.HasSuffix(strings.ToLower(file.Name), ".xml") {
			rc, err := file.Open()
			if err != nil {
				return "", err
			}
			defer rc.Close()
			cdrContent, err := io.ReadAll(rc)
			if err != nil {
				return "", err
			}
			return string(cdrContent), nil // ¡Éxito!
		}
	}

	return "", fmt.Errorf("no se encontró ningún archivo XML dentro del ZIP del CDR")
}
