package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"

	"github.com/beevik/etree"
)

const (
	keyFilePath  = "./certs/private_pkcs8.key"
	certFilePath = "./certs/public.pem"
)

func ProcesarDocumento(doc *DocumentoElectronico) ([]byte, error) {
	// 1. Construir el esqueleto del XML con etree
	xmlDoc := buildXML(doc)

	// 2. Firmar el XML
	xmlFirmado, err := firmarXML(xmlDoc, keyFilePath, certFilePath)
	if err != nil {
		return nil, err
	}

	return xmlFirmado, nil
}

// ======================================================================
// FUNCIÓN firmarXML CORREGIDA CON CANONICALIZACIÓN CORRECTA
// ======================================================================

func firmarXML(doc *etree.Document, keyFile, certFile string) ([]byte, error) {
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("leyendo keyFile: %w", err)
	}
	block, _ := pem.Decode(keyData)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error al parsear clave: %v", err)
	}
	rsaPrivateKey, _ := key.(*rsa.PrivateKey)

	certData, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("leyendo certFile: %w", err)
	}
	block, _ = pem.Decode(certData)
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	// 1. Quitar el bloque de firma para calcular el digest del documento
	signatureNodeOriginal := doc.FindElement("//ds:Signature")
	if signatureNodeOriginal == nil {
		return nil, fmt.Errorf("no se encontró el nodo ds:Signature en el documento")
	}
	extContentNode := signatureNodeOriginal.Parent()
	extContentNode.RemoveChild(signatureNodeOriginal)

	// 2. Calcular digest del ELEMENTO RAÍZ del documento (sin la declaración <?xml...?>)
	// ===== ESTA ES LA CORRECCIÓN MÁS IMPORTANTE =====
	rootElement := doc.Root()
	if rootElement == nil {
		return nil, fmt.Errorf("el documento no tiene un elemento raíz")
	}

	c14nSettings := etree.WriteSettings{CanonicalText: true}
	var buf bytes.Buffer
	rootElement.WriteTo(&buf, &c14nSettings) // Escribimos solo el elemento raíz, no todo el doc.

	h := sha1.New()
	h.Write(buf.Bytes())
	digest := base64.StdEncoding.EncodeToString(h.Sum(nil))
	// ===== FIN DE LA CORRECCIÓN MÁS IMPORTANTE =====

	// 3. Re-insertar el bloque de firma y rellenar los valores
	extContentNode.AddChild(signatureNodeOriginal)
	doc.FindElement("//ds:DigestValue").SetText(digest)
	doc.FindElement("//ds:X509Certificate").SetText(base64.StdEncoding.EncodeToString(certificate.Raw))

	// 4. "Canonicalizar" y firmar el SignedInfo de forma AISLADA (esto ya era correcto)
	signedInfoNode := doc.FindElement("//ds:SignedInfo")
	tempDoc := etree.NewDocument()
	tempDoc.SetRoot(signedInfoNode.Copy())
	tempDoc.WriteSettings.CanonicalText = true
	var signedInfoBuf bytes.Buffer
	tempDoc.WriteTo(&signedInfoBuf)

	hSignedInfo := sha1.New()
	hSignedInfo.Write(signedInfoBuf.Bytes())

	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, crypto.SHA1, hSignedInfo.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("error al firmar hash: %v", err)
	}

	doc.FindElement("//ds:SignatureValue").SetText(base64.StdEncoding.EncodeToString(signature))

	// 5. Devolver el XML final en formato CANÓNICO (esto ya era correcto)
	doc.WriteSettings.CanonicalText = true
	return doc.WriteToBytes()
}

// ======================================================================
// FUNCIÓN buildXML CORREGIDA CON ESTRUCTURA ESPERADA POR SUNAT
// ======================================================================

func buildXML(d *DocumentoElectronico) *etree.Document {
	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)

	root := doc.CreateElement("Invoice")
	addNamespaces(root) // Usar la función de namespaces corregida

	// UBLExtensions (Estructura corregida)
	exts := root.CreateElement("ext:UBLExtensions")

	// Primer UBLExtension con sac:AdditionalInformation (puede estar vacío)
	ext1 := exts.CreateElement("ext:UBLExtension")
	content1 := ext1.CreateElement("ext:ExtensionContent")
	content1.CreateElement("sac:AdditionalInformation")

	// --- BLOQUE DE FIRMA RESTAURADO ---
	// Segundo UBLExtension para la firma
	ext2 := exts.CreateElement("ext:UBLExtension")
	content2 := ext2.CreateElement("ext:ExtensionContent")
	sigNode := content2.CreateElement("ds:Signature")
	sigNode.CreateAttr("Id", "SignatureSP") // ID de firma

	signedInfo := sigNode.CreateElement("ds:SignedInfo")
	cm := signedInfo.CreateElement("ds:CanonicalizationMethod")
	cm.CreateAttr("Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
	sm := signedInfo.CreateElement("ds:SignatureMethod")
	sm.CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#rsa-sha1")
	ref := signedInfo.CreateElement("ds:Reference")
	ref.CreateAttr("URI", "")
	transforms := ref.CreateElement("ds:Transforms")
	tr := transforms.CreateElement("ds:Transform")
	tr.CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature")
	dm := ref.CreateElement("ds:DigestMethod")
	dm.CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#sha1")
	ref.CreateElement("ds:DigestValue") // Se llena en firmarXML

	sigNode.CreateElement("ds:SignatureValue") // Se llena en firmarXML

	keyInfo := sigNode.CreateElement("ds:KeyInfo")
	x509Data := keyInfo.CreateElement("ds:X509Data")
	x509Data.CreateElement("ds:X509Certificate") // Se llena en firmarXML
	// --- FIN DE BLOQUE DE FIRMA RESTAURADO ---

	// Cabecera del documento
	root.CreateElement("cbc:UBLVersionID").SetText("2.1")
	root.CreateElement("cbc:CustomizationID").SetText("2.0")
	root.CreateElement("cbc:ID").SetText(fmt.Sprintf("%s-%s", d.Serie, d.Correlativo))
	root.CreateElement("cbc:IssueDate").SetText(d.FechaEmision)

	itc := root.CreateElement("cbc:InvoiceTypeCode")
	itc.CreateAttr("listID", "0101")
	itc.CreateAttr("listAgencyName", "PE:SUNAT")
	itc.CreateAttr("listName", "Tipo de Documento")
	itc.CreateAttr("listURI", "urn:pe:gob:sunat:cpe:see:gem:catalogos:catalogo01")
	itc.SetText(d.TipoDocumento)

	for _, l := range d.Leyendas {
		note := root.CreateElement("cbc:Note")
		note.CreateAttr("languageLocaleID", l.Codigo)
		note.SetCData(l.Valor)
	}
	dcc := root.CreateElement("cbc:DocumentCurrencyCode")
	dcc.CreateAttr("listID", "ISO 4217 Alpha")
	dcc.CreateAttr("listName", "Currency")
	dcc.CreateAttr("listAgencyName", "United Nations Economic Commission for Europe")
	dcc.SetText(d.Moneda)

	// Signature (cac)
	cacSign := root.CreateElement("cac:Signature")
	cacSign.CreateElement("cbc:ID").SetText(fmt.Sprintf("%s-%s-%s", d.Emisor.RUC, d.Serie, d.Correlativo))
	sp := cacSign.CreateElement("cac:SignatoryParty")
	pi := sp.CreateElement("cac:PartyIdentification")
	pi.CreateElement("cbc:ID").SetText(d.Emisor.RUC)
	pn := sp.CreateElement("cac:PartyName")
	pn.CreateElement("cbc:Name").SetCData(d.Emisor.RazonSocial)
	dsa := cacSign.CreateElement("cac:DigitalSignatureAttachment")
	er := dsa.CreateElement("cac:ExternalReference")
	er.CreateElement("cbc:URI").SetText("#SignatureSP")

	// Emisor y Receptor
	buildParty(root, "cac:AccountingSupplierParty", d.Emisor)
	buildParty(root, "cac:AccountingCustomerParty", d.Receptor)

	// Totales
	tt := root.CreateElement("cac:TaxTotal")
	ta := tt.CreateElement("cbc:TaxAmount")
	ta.CreateAttr("currencyID", d.Moneda)
	ta.SetText(fmt.Sprintf("%.2f", d.TotalIGV))

	ts := tt.CreateElement("cac:TaxSubtotal")
	tsa := ts.CreateElement("cbc:TaxableAmount")
	tsa.CreateAttr("currencyID", d.Moneda)
	tsa.SetText(fmt.Sprintf("%.2f", d.TotalGravado))
	tsa2 := ts.CreateElement("cbc:TaxAmount")
	tsa2.CreateAttr("currencyID", d.Moneda)
	tsa2.SetText(fmt.Sprintf("%.2f", d.TotalIGV))
	tc := ts.CreateElement("cac:TaxCategory")
	tcs := tc.CreateElement("cac:TaxScheme")
	tcs_id := tcs.CreateElement("cbc:ID")
	tcs_id.CreateAttr("schemeID", "UN/ECE 5153")
	tcs_id.CreateAttr("schemeAgencyName", "PE:SUNAT")
	tcs_id.SetText("1000")
	tcs.CreateElement("cbc:Name").SetText("IGV")
	tcs.CreateElement("cbc:TaxTypeCode").SetText("VAT")

	lmt := root.CreateElement("cac:LegalMonetaryTotal")
	lmtLineExt := lmt.CreateElement("cbc:LineExtensionAmount")
	lmtLineExt.CreateAttr("currencyID", d.Moneda)
	lmtLineExt.SetText(fmt.Sprintf("%.2f", d.TotalGravado))

	lmtPayable := lmt.CreateElement("cbc:PayableAmount")
	lmtPayable.CreateAttr("currencyID", d.Moneda)
	lmtPayable.SetText(fmt.Sprintf("%.2f", d.TotalGeneral))

	// Detalles
	for i, item := range d.Detalles {
		il := root.CreateElement("cac:InvoiceLine")
		il.CreateElement("cbc:ID").SetText(strconv.Itoa(i + 1))

		ilQty := il.CreateElement("cbc:InvoicedQuantity")
		ilQty.CreateAttr("unitCode", item.UnidadMedida)
		ilQty.CreateAttr("unitCodeListID", "UN/ECE rec 20")
		ilQty.CreateAttr("unitCodeListAgencyName", "United Nations Economic Commission for Europe")
		ilQty.SetText(fmt.Sprintf("%.2f", item.Cantidad))

		ilExt := il.CreateElement("cbc:LineExtensionAmount")
		ilExt.CreateAttr("currencyID", d.Moneda)
		ilExt.SetText(fmt.Sprintf("%.2f", item.ValorTotal))

		pr := il.CreateElement("cac:PricingReference")
		acp := pr.CreateElement("cac:AlternativeConditionPrice")
		pa := acp.CreateElement("cbc:PriceAmount")
		pa.CreateAttr("currencyID", d.Moneda)
		pa.SetText(fmt.Sprintf("%.2f", item.PrecioUnitario))
		ptc := acp.CreateElement("cbc:PriceTypeCode")
		ptc.CreateAttr("listName", "Tipo de Precio")
		ptc.CreateAttr("listAgencyName", "PE:SUNAT")
		ptc.CreateAttr("listURI", "urn:pe:gob:sunat:cpe:see:gem:catalogos:catalogo16")
		ptc.SetText("01")

		itt := il.CreateElement("cac:TaxTotal")
		ita := itt.CreateElement("cbc:TaxAmount")
		ita.CreateAttr("currencyID", d.Moneda)
		ita.SetText(fmt.Sprintf("%.2f", item.IGV))

		its := itt.CreateElement("cac:TaxSubtotal")
		itsa := its.CreateElement("cbc:TaxableAmount")
		itsa.CreateAttr("currencyID", d.Moneda)
		itsa.SetText(fmt.Sprintf("%.2f", item.ValorTotal))
		itsa2 := its.CreateElement("cbc:TaxAmount")
		itsa2.CreateAttr("currencyID", d.Moneda)
		itsa2.SetText(fmt.Sprintf("%.2f", item.IGV))

		itc_det := its.CreateElement("cac:TaxCategory")
		itc_det.CreateElement("cbc:Percent").SetText("18.00")
		terc := itc_det.CreateElement("cbc:TaxExemptionReasonCode")
		terc.CreateAttr("listAgencyName", "PE:SUNAT")
		terc.CreateAttr("listName", "Afectacion del IGV")
		terc.CreateAttr("listURI", "urn:pe:gob:sunat:cpe:see:gem:catalogos:catalogo07")
		terc.SetText(item.AfectacionIGV)

		itsch := itc_det.CreateElement("cac:TaxScheme")
		itsch_id := itsch.CreateElement("cbc:ID")
		itsch_id.CreateAttr("schemeID", "UN/ECE 5153")
		itsch_id.CreateAttr("schemeAgencyName", "PE:SUNAT")
		itsch_id.SetText("1000")
		itsch.CreateElement("cbc:Name").SetText("IGV")
		itsch.CreateElement("cbc:TaxTypeCode").SetText("VAT")

		iitem := il.CreateElement("cac:Item")
		iitem.CreateElement("cbc:Description").SetCData(item.Descripcion)

		iprice := il.CreateElement("cac:Price")
		ipa := iprice.CreateElement("cbc:PriceAmount")
		ipa.CreateAttr("currencyID", d.Moneda)
		ipa.SetText(fmt.Sprintf("%.2f", item.ValorUnitario))
	}

	return doc
}

// ======================================================================
// FUNCIÓN addNamespaces CORREGIDA
// ======================================================================
func addNamespaces(root *etree.Element) {
	root.CreateAttr("xmlns", "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2")
	root.CreateAttr("xmlns:cac", "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2")
	root.CreateAttr("xmlns:cbc", "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2")
	root.CreateAttr("xmlns:ccts", "urn:un:unece:uncefact:documentation:2")
	root.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	root.CreateAttr("xmlns:ext", "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2")
	root.CreateAttr("xmlns:qdt", "urn:oasis:names:specification:ubl:schema:xsd:QualifiedDataTypes-2")
	root.CreateAttr("xmlns:sac", "urn:sunat:names:specification:ubl:peru:schema:xsd:SunatAggregateComponents-1")
	root.CreateAttr("xmlns:udt", "urn:un:unece:uncefact:data:specification:UnqualifiedDataTypesSchemaModule:2")
}

// ======================================================================
// FUNCIÓN buildParty CORREGIDA
// ======================================================================
func buildParty(root *etree.Element, partyType string, data Empresa) {
	p := root.CreateElement(partyType)
	party := p.CreateElement("cac:Party")
	pi := party.CreateElement("cac:PartyIdentification")
	id := pi.CreateElement("cbc:ID")
	id.CreateAttr("schemeID", data.TipoDocIdentidad)
	id.CreateAttr("schemeName", "Documento de Identidad")
	id.CreateAttr("schemeAgencyName", "PE:SUNAT")
	id.CreateAttr("schemeURI", "urn:pe:gob:sunat:cpe:see:gem:catalogos:catalogo06")
	id.SetText(data.RUC)
	ple := party.CreateElement("cac:PartyLegalEntity")
	ple.CreateElement("cbc:RegistrationName").SetCData(data.RazonSocial)
}

// El resto del código no necesita cambios
func calcularHash(data []byte) string {
	hasher := sha256.New()
	hasher.Write(data)
	return hex.EncodeToString(hasher.Sum(nil))
}
