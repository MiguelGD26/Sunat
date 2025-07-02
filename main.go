package main

import (
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/convertir", convertirHandler)
	port := "8080"
	log.Printf("Servidor iniciado. Escuchando en http://localhost:%s", port)
	log.Println("Endpoint disponible en: POST /convertir")
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("No se pudo iniciar el servidor: %v", err)
	}
}
