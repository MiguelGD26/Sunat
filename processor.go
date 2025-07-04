package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"
)

const (
	keyFilePath  = "./certs/private_pkcs8.key"
	certFilePath = "./certs/public.pem"
)

// ProcesarDocumento orquesta la creación, firma y codificación.
func ProcesarDocumento(docIn *DocumentoElectronico) ([]byte, error) {
	xmlDoc := buildXML(docIn)
	signedDoc, err := firmarXML(xmlDoc, keyFilePath, certFilePath)
	if err != nil {
		return nil, fmt.Errorf("error al firmar documento: %w", err)
	}

	utf8Bytes, err := signedDoc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("error al serializar XML a bytes UTF-8: %w", err)
	}

	encoder := charmap.ISO8859_1.NewEncoder()
	isoBytes, _, err := transform.Bytes(encoder, utf8Bytes)
	if err != nil {
		return nil, fmt.Errorf("error al convertir a ISO-8859-1: %w", err)
	}

	return isoBytes, nil
}

// firmarXML usa la librería goxmldsig con la configuración correcta y mueve el nodo.
func firmarXML(doc *etree.Document, keyFile, certFile string) (*etree.Document, error) {
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyData)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPrivateKey := key.(*rsa.PrivateKey)

	certData, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	block, _ = pem.Decode(certData)
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	certChain := [][]byte{certificate.Raw}
	ctx, err := dsig.NewSigningContext(rsaPrivateKey, certChain)
	if err != nil {
		return nil, err
	}

	ctx.Canonicalizer = dsig.MakeC14N10RecCanonicalizer()
	ctx.Hash = crypto.SHA1

	// Preparamos el nodo Signature con el ID correcto ANTES de firmar.
	signaturePlaceholder := doc.FindElement("//ds:Signature")
	if signaturePlaceholder == nil {
		return nil, fmt.Errorf("buildXML no creó el placeholder ds:Signature")
	}
	signaturePlaceholder.CreateAttr("Id", "SignSUNAT")

	signedRoot, err := ctx.SignEnveloped(doc.Root())
	if err != nil {
		return nil, fmt.Errorf("error al llamar a SignEnveloped: %w", err)
	}

	// La librería inyecta la firma en el placeholder, no necesitamos moverla.

	// Actualizamos la referencia en <cac:Signature>
	cacSignRefNode := signedRoot.FindElement("./cac:Signature/cac:DigitalSignatureAttachment/cac:ExternalReference/cbc:URI")
	if cacSignRefNode != nil {
		cacSignRefNode.SetText("SignSUNAT")
	}

	finalDoc := etree.NewDocument()

	finalDoc.CreateProcInst("xml", `version="1.0" encoding="ISO-8859-1" standalone="no"`)
	finalDoc.CreateProcInst("xml-stylesheet", `type="text/xsl" href="factura2.1.xsl"`)
	finalDoc.SetRoot(signedRoot)
	return finalDoc, nil
}

// buildXML construye la estructura del documento UBL Invoice.
func buildXML(d *DocumentoElectronico) *etree.Document {
	doc := etree.NewDocument()

	root := doc.CreateElement("Invoice")
	addNamespaces(root)

	exts := root.CreateElement("ext:UBLExtensions")
	ext1 := exts.CreateElement("ext:UBLExtension")
	content1 := ext1.CreateElement("ext:ExtensionContent")
	content1.CreateElement("sac:AdditionalInformation")

	ext2 := exts.CreateElement("ext:UBLExtension")
	content2 := ext2.CreateElement("ext:ExtensionContent")
	// Dejamos un placeholder que la librería de firma encontrará y llenará.
	content2.CreateElement("ds:Signature")

	root.CreateElement("cbc:UBLVersionID").SetText("2.1")
	root.CreateElement("cbc:CustomizationID").SetText("2.0")
	root.CreateElement("cbc:ID").SetText(fmt.Sprintf("%s-%s", d.Serie, d.Correlativo))
	root.CreateElement("cbc:IssueDate").SetText(d.FechaEmision)
	root.CreateElement("cbc:IssueTime").SetText(time.Now().UTC().Format("15:04:05.0Z"))

	itc := root.CreateElement("cbc:InvoiceTypeCode")
	itc.CreateAttr("listAgencyName", "PE:SUNAT")
	itc.CreateAttr("listID", "0101")
	itc.CreateAttr("listName", "Tipo de Documento")
	itc.CreateAttr("listURI", "urn:pe:gob:sunat:cpe:see:gem:catalogos:catalogo01")
	itc.CreateAttr("name", "Tipo de Operacion")
	itc.SetText(d.TipoDocumento)

	for _, l := range d.Leyendas {
		note := root.CreateElement("cbc:Note")
		note.CreateAttr("languageLocaleID", l.Codigo)
		note.SetText(l.Valor)
	}
	dcc := root.CreateElement("cbc:DocumentCurrencyCode")
	dcc.CreateAttr("listID", "ISO 4217 Alpha")
	dcc.CreateAttr("listName", "Currency")
	dcc.CreateAttr("listAgencyName", "United Nations Economic Commission for Europe")
	dcc.SetText(d.Moneda)

	cacSign := root.CreateElement("cac:Signature")
	cacSign.CreateElement("cbc:ID").SetText(fmt.Sprintf("%s-%s", d.Serie, d.Correlativo))
	sp := cacSign.CreateElement("cac:SignatoryParty")
	pi := sp.CreateElement("cac:PartyIdentification")
	pi.CreateElement("cbc:ID").SetText(d.Emisor.RUC)
	pn := sp.CreateElement("cac:PartyName")
	pn.CreateElement("cbc:Name").SetText(d.Emisor.RazonSocial)
	dsa := cacSign.CreateElement("cac:DigitalSignatureAttachment")
	er := dsa.CreateElement("cac:ExternalReference")
	er.CreateElement("cbc:URI").SetText("")

	buildParty(root, "cac:AccountingSupplierParty", d.Emisor)
	buildParty(root, "cac:AccountingCustomerParty", d.Receptor)

	tt := root.CreateElement("cac:TaxTotal")
	ta := tt.CreateElement("cbc:TaxAmount")
	ta.CreateAttr("currencyID", d.Moneda)
	ta.SetText(d.TotalIGV.StringFixed(2))

	ts := tt.CreateElement("cac:TaxSubtotal")
	tsa := ts.CreateElement("cbc:TaxableAmount")
	tsa.CreateAttr("currencyID", d.Moneda)
	tsa.SetText(d.TotalGravado.StringFixed(2))
	tsa2 := ts.CreateElement("cbc:TaxAmount")
	tsa2.CreateAttr("currencyID", d.Moneda)
	tsa2.SetText(d.TotalIGV.StringFixed(2))
	tc := ts.CreateElement("cac:TaxCategory")

	tc_id_cat := tc.CreateElement("cbc:ID")
	tc_id_cat.CreateAttr("schemeID", "UN/ECE 5305")
	tc_id_cat.CreateAttr("schemeName", "Tax Category Identifier")
	tc_id_cat.CreateAttr("schemeAgencyName", "United Nations Economic Commission for Europe")
	tc_id_cat.SetText("S")

	tcs := tc.CreateElement("cac:TaxScheme")
	tcs_id := tcs.CreateElement("cbc:ID")
	tcs_id.CreateAttr("schemeID", "UN/ECE 5153")
	tcs_id.CreateAttr("schemeName", "Codigo de tributos")
	tcs_id.CreateAttr("schemeAgencyName", "PE:SUNAT")
	tcs_id.SetText("1000")
	tcs.CreateElement("cbc:Name").SetText("IGV")
	tcs.CreateElement("cbc:TaxTypeCode").SetText("VAT")

	lmt := root.CreateElement("cac:LegalMonetaryTotal")
	lmtLineExt := lmt.CreateElement("cbc:LineExtensionAmount")
	lmtLineExt.CreateAttr("currencyID", d.Moneda)
	lmtLineExt.SetText(d.TotalGravado.StringFixed(2))

	lmtPayable := lmt.CreateElement("cbc:PayableAmount")
	lmtPayable.CreateAttr("currencyID", d.Moneda)
	lmtPayable.SetText(d.TotalGeneral.StringFixed(2))

	for i, item := range d.Detalles {
		il := root.CreateElement("cac:InvoiceLine")
		il.CreateElement("cbc:ID").SetText(strconv.Itoa(i + 1))
		ilQty := il.CreateElement("cbc:InvoicedQuantity")
		ilQty.CreateAttr("unitCode", item.UnidadMedida)
		ilQty.CreateAttr("unitCodeListID", "UN/ECE rec 20")
		ilQty.CreateAttr("unitCodeListAgencyName", "United Nations Economic Commission for Europe")
		ilQty.SetText(item.Cantidad.StringFixed(2))
		ilExt := il.CreateElement("cbc:LineExtensionAmount")
		ilExt.CreateAttr("currencyID", d.Moneda)
		ilExt.SetText(item.ValorTotal.StringFixed(2))
		pr := il.CreateElement("cac:PricingReference")
		acp := pr.CreateElement("cac:AlternativeConditionPrice")
		pa := acp.CreateElement("cbc:PriceAmount")
		pa.CreateAttr("currencyID", d.Moneda)
		pa.SetText(item.PrecioUnitario.StringFixed(2))
		ptc := acp.CreateElement("cbc:PriceTypeCode")
		ptc.CreateAttr("listName", "Tipo de Precio")
		ptc.CreateAttr("listAgencyName", "PE:SUNAT")
		ptc.CreateAttr("listURI", "urn:pe:gob:sunat:cpe:see:gem:catalogos:catalogo16")
		ptc.SetText("01")
		itt := il.CreateElement("cac:TaxTotal")
		ita := itt.CreateElement("cbc:TaxAmount")
		ita.CreateAttr("currencyID", d.Moneda)
		ita.SetText(item.IGV.StringFixed(2))
		its := itt.CreateElement("cac:TaxSubtotal")
		itsa := its.CreateElement("cbc:TaxableAmount")
		itsa.CreateAttr("currencyID", d.Moneda)
		itsa.SetText(item.ValorTotal.StringFixed(2))
		itsa2 := its.CreateElement("cbc:TaxAmount")
		itsa2.CreateAttr("currencyID", d.Moneda)
		itsa2.SetText(item.IGV.StringFixed(2))
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
		iitem.CreateElement("cbc:Description").SetText(item.Descripcion)
		iprice := il.CreateElement("cac:Price")
		ipa := iprice.CreateElement("cbc:PriceAmount")
		ipa.CreateAttr("currencyID", d.Moneda)
		ipa.SetText(item.ValorUnitario.StringFixed(10))
	}
	return doc
}

// --- Funciones de ayuda (addNamespaces, buildParty, calcularHash) ---

func addNamespaces(root *etree.Element) {
	root.CreateAttr("xmlns", "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2")
	root.CreateAttr("xmlns:cac", "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2")
	root.CreateAttr("xmlns:cbc", "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2")
	root.CreateAttr("xmlns:ccts", "urn:oasis:names:specification:ubl:schema:xsd:CoreComponentParameters-2")
	root.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	root.CreateAttr("xmlns:ext", "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2")
	root.CreateAttr("xmlns:qdt", "urn:oasis:names:specification:ubl:schema:xsd:QualifiedDataTypes-2")
	root.CreateAttr("xmlns:sac", "urn:sunat:names:specification:ubl:peru:schema:xsd:SunatAggregateComponents-1")
	root.CreateAttr("xmlns:stat", "urn:oasis:names:specification:ubl:schema:xsd:DocumentStatusCode-1.0")
	root.CreateAttr("xmlns:udt", "urn:un:unece:uncefact:data:draft:UnqualifiedDataTypesSchemaModule:2")
}

func buildParty(root *etree.Element, partyType string, data Empresa) {
	p := root.CreateElement(partyType)
	party := p.CreateElement("cac:Party")

	if data.NombreComercial != "" {
		pn := party.CreateElement("cac:PartyName")
		pn.CreateElement("cbc:Name").SetText(data.NombreComercial)
	}

	pi := party.CreateElement("cac:PartyIdentification")
	id := pi.CreateElement("cbc:ID")
	id.CreateAttr("schemeID", data.TipoDocIdentidad)
	id.CreateAttr("schemeName", "Documento de Identidad")
	id.CreateAttr("schemeAgencyName", "PE:SUNAT")
	id.CreateAttr("schemeURI", "urn:pe:gob:sunat:cpe:see:gem:catalogos:catalogo06")
	id.SetText(data.RUC)

	ple := party.CreateElement("cac:PartyLegalEntity")
	ple.CreateElement("cbc:RegistrationName").SetText(data.RazonSocial)

	addr := ple.CreateElement("cac:RegistrationAddress")
	addr.CreateElement("cbc:AddressTypeCode").SetText(data.Direccion.CodLocal)
	addr.CreateElement("cbc:CitySubdivisionName").SetText("-")
	addr.CreateElement("cbc:CityName").SetText(data.Direccion.Provincia)
	addr.CreateElement("cbc:CountrySubentity").SetText(data.Direccion.Departamento)
	addr.CreateElement("cbc:District").SetText(data.Direccion.Distrito)
	al := addr.CreateElement("cac:AddressLine")
	al.CreateElement("cbc:Line").SetText(data.Direccion.Direccion)
	country := addr.CreateElement("cac:Country")
	country.CreateElement("cbc:IdentificationCode").SetText("PE")
}

func calcularHash(data []byte) string {
	hasher := sha256.New()
	hasher.Write(data)
	return hex.EncodeToString(hasher.Sum(nil))
}
