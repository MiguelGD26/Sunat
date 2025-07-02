package main

// ENTRADA JSON (SIN CAMBIOS)
type DocumentoElectronico struct {
	TipoDocumento          string    `json:"tipoDocumento"`
	Serie                  string    `json:"serie"`
	Correlativo            string    `json:"correlativo"`
	FechaEmision           string    `json:"fechaEmision"`
	Moneda                 string    `json:"moneda"`
	Emisor                 Empresa   `json:"emisor"`
	Receptor               Empresa   `json:"receptor"`
	TotalGravado           float64   `json:"totalGravado"`
	TotalIGV               float64   `json:"totalIGV"`
	TotalGeneral           float64   `json:"totalGeneral"`
	Detalles               []Detalle `json:"detalles"`
	Leyendas               []Leyenda `json:"leyendas"`
	DocAfectadoSerie       string    `json:"docAfectadoSerie,omitempty"`
	DocAfectadoCorrelativo string    `json:"docAfectadoCorrelativo,omitempty"`
	DocAfectadoTipo        string    `json:"docAfectadoTipo,omitempty"`
	MotivoNotaCredito      string    `json:"motivoNotaCredito,omitempty"`
}
type Empresa struct {
	TipoDocIdentidad string `json:"tipoDocIdentidad"`
	RUC              string `json:"ruc"`
	RazonSocial      string `json:"razonSocial"`
	Direccion        string `json:"direccion"`
}
type Detalle struct {
	ID             int     `json:"id"`
	CodigoProducto string  `json:"codigoProducto"`
	Descripcion    string  `json:"descripcion"`
	UnidadMedida   string  `json:"unidadMedida"`
	Cantidad       float64 `json:"cantidad"`
	ValorUnitario  float64 `json:"valorUnitario"`
	PrecioUnitario float64 `json:"precioUnitario"`
	ValorTotal     float64 `json:"valorTotal"`
	AfectacionIGV  string  `json:"afectacionIGV"`
	IGV            float64 `json:"igv"`
}
type Leyenda struct {
	Codigo string `json:"codigo"`
	Valor  string `json:"valor"`
}

// RESPUESTAS JSON (SIN CAMBIOS)
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
