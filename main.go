package main

import (
	"log"
	"net/http"
	"os" // Asegúrate de tener esta importación
)

// Variables de configuración para las credenciales de SUNAT
// Es mejor sacarlas del código para poder cambiarlas fácilmente.
const (
	RUC_EMISOR = "20601546913" // Tu RUC de prueba
	USER_SOL   = "MODDATOS"    // Tu usuario SOL de prueba
	PASS_SOL   = "MODDATOS"    // Tu clave SOL de prueba (el cliente la ignora y usa el RUC para el billService)
)

func main() {
	// Crear el cliente de SUNAT una sola vez.
	sunatClient := NewClient(RUC_EMISOR, USER_SOL, PASS_SOL)

	// Crear el directorio de almacenamiento si no existe
	if err := os.MkdirAll("./storage", 0755); err != nil {
		log.Fatalf("No se pudo crear el directorio de almacenamiento: %v", err)
	}

	// Inyectar el cliente al handler
	http.HandleFunc("/convertir", convertirHandler(sunatClient))

	log.Println("Servidor iniciado. Escuchando en http://localhost:8080")
	log.Println("Endpoint disponible en: POST /convertir")

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Error al iniciar el servidor: %v", err)
	}
}
