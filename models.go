package main

import "github.com/shopspring/decimal"

// DocumentoElectronico define la estructura principal de la entrada JSON.
type DocumentoElectronico struct {
	TipoDocumento          string          `json:"tipoDocumento"`
	Serie                  string          `json:"serie"`
	Correlativo            string          `json:"correlativo"`
	FechaEmision           string          `json:"fechaEmision"`
	Moneda                 string          `json:"moneda"`
	Emisor                 Empresa         `json:"emisor"`
	Receptor               Empresa         `json:"receptor"`
	TotalGravado           decimal.Decimal `json:"totalGravado"`
	TotalIGV               decimal.Decimal `json:"totalIGV"`
	TotalGeneral           decimal.Decimal `json:"totalGeneral"`
	Detalles               []Detalle       `json:"detalles"`
	Leyendas               []Leyenda       `json:"leyendas"`
	DocAfectadoSerie       string          `json:"docAfectadoSerie,omitempty"`
	DocAfectadoCorrelativo string          `json:"docAfectadoCorrelativo,omitempty"`
	DocAfectadoTipo        string          `json:"docAfectadoTipo,omitempty"`
	MotivoNotaCredito      string          `json:"motivoNotaCredito,omitempty"`
}

// Empresa contiene los datos del emisor o receptor, incluyendo la dirección estructurada.
type Empresa struct {
	TipoDocIdentidad string    `json:"tipoDocIdentidad"`
	RUC              string    `json:"ruc"`
	RazonSocial      string    `json:"razonSocial"`
	NombreComercial  string    `json:"nombreComercial,omitempty"`
	Direccion        Direccion `json:"direccion"`
}

// Direccion define los campos de una dirección fiscal.
type Direccion struct {
	Ubigeo       string `json:"ubigeo"`
	Departamento string `json:"departamento"`
	Provincia    string `json:"provincia"`
	Distrito     string `json:"distrito"`
	Urbanizacion string `json:"urbanizacion"`
	Direccion    string `json:"direccion"`
	CodLocal     string `json:"codLocal"`
}

// Detalle define una línea del comprobante.
type Detalle struct {
	ID             int             `json:"id"`
	CodigoProducto string          `json:"codigoProducto"`
	Descripcion    string          `json:"descripcion"`
	UnidadMedida   string          `json:"unidadMedida"`
	Cantidad       decimal.Decimal `json:"cantidad"`
	ValorUnitario  decimal.Decimal `json:"valorUnitario"`
	PrecioUnitario decimal.Decimal `json:"precioUnitario"`
	ValorTotal     decimal.Decimal `json:"valorTotal"`
	AfectacionIGV  string          `json:"afectacionIGV"`
	IGV            decimal.Decimal `json:"igv"`
}

// Leyenda define una leyenda del comprobante.
type Leyenda struct {
	Codigo string `json:"codigo"`
	Valor  string `json:"valor"`
}

// RespuestaExito y RespuestaError definen las respuestas de la API.
type RespuestaExito struct {
	Status        string `json:"status"`
	CorrelationId string `json:"correlationId"`
	DocumentId    string `json:"documentId"`
	XmlPath       string `json:"xmlPath"`
	XmlHash       string `json:"xmlHash"`
	ProcessedAt   string `json:"processedAt"`
	SunatCDR      string `json:"sunatCdr,omitempty"`
}
type RespuestaError struct {
	Status        string `json:"status"`
	CorrelationId string `json:"correlationId"`
	ErrorCode     string `json:"errorCode"`
	ErrorMessage  string `json:"errorMessage"`
}
