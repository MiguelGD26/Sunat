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

const sunatBetaURL = "https://e-beta.sunat.gob.pe/ol-ti-itcpfegem-beta/billService"

func EnviarFacturaSUNAT(nombreArchivoZIP, nombreArchivoXML string, xmlFirmado []byte, rucEmisor string) (string, error) {
	zipData, err := crearZip(nombreArchivoXML, xmlFirmado)
	if err != nil {
		return "", fmt.Errorf("error al crear el archivo ZIP: %v", err)
	}

	usuarioSOL := rucEmisor + "MODDATOS"
	claveSOL := rucEmisor
	soapRequest, err := construirSOAPRequest(nombreArchivoZIP, zipData, usuarioSOL, claveSOL)
	if err != nil {
		return "", fmt.Errorf("error al construir la petición SOAP: %v", err)
	}

	httpClient := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("POST", sunatBetaURL, bytes.NewBuffer(soapRequest))
	if err != nil {
		return "", fmt.Errorf("error al crear la petición HTTP: %v", err)
	}
	req.Header.Set("Content-Type", "text/xml;charset=UTF-8")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error al enviar la petición a SUNAT: %v", err)
	}
	defer resp.Body.Close()

	soapResponse, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error al leer la respuesta de SUNAT: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		if strings.Contains(string(soapResponse), "faultcode") {
			return "", fmt.Errorf("SUNAT respondió con un error SOAP: %s", soapResponse)
		}
		return "", fmt.Errorf("SUNAT respondió con estado HTTP %d: %s", resp.StatusCode, soapResponse)
	}

	cdrXML, err := procesarRespuestaSUNAT(soapResponse)
	if err != nil {
		return "", fmt.Errorf("error al procesar la respuesta de SUNAT: %v", err)
	}

	return cdrXML, nil
}

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

func construirSOAPRequest(nombreZip string, zipData []byte, usuario, password string) ([]byte, error) {
	soapTemplate := `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ser="http://service.sunat.gob.pe" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><soapenv:Header><wsse:Security><wsse:UsernameToken><wsse:Username>%s</wsse:Username><wsse:Password>%s</wsse:Password></wsse:UsernameToken></wsse:Security></soapenv:Header><soapenv:Body><ser:sendBill><fileName>%s</fileName><contentFile>%s</contentFile></ser:sendBill></soapenv:Body></soapenv:Envelope>`
	zipBase64 := base64.StdEncoding.EncodeToString(zipData)
	return []byte(fmt.Sprintf(soapTemplate, usuario, password, nombreZip, zipBase64)), nil
}

func procesarRespuestaSUNAT(soapResponse []byte) (string, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(soapResponse); err != nil {
		return "", fmt.Errorf("XML de respuesta SOAP mal formado: %v", err)
	}
	cdrNode := doc.FindElement("//applicationResponse")
	if cdrNode == nil {
		// return "", fmt.Errorf("no se encontró el nodo <applicationResponse> en la respuesta de SUNAT")
		return "", fmt.Errorf("no se encontró el nodo <applicationResponse> en la respuesta de SUNAT. Respuesta completa: %s", string(soapResponse))

	}
	cdrZipBytes, err := base64.StdEncoding.DecodeString(cdrNode.Text())
	if err != nil {
		return "", fmt.Errorf("no se pudo decodificar el CDR en Base64: %v", err)
	}
	zipReader, err := zip.NewReader(bytes.NewReader(cdrZipBytes), int64(len(cdrZipBytes)))
	if err != nil {
		return "", fmt.Errorf("no se pudo leer el ZIP del CDR: %v", err)
	}
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
			return string(cdrContent), nil
		}
	}
	return "", fmt.Errorf("no se encontró ningún archivo XML dentro del ZIP del CDR")
}
