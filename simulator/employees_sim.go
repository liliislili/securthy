package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type SimEmployee struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	DeviceIP string `json:"device_ip"`
	Role     string `json:"role"`
}

var simulatedEmployees = []SimEmployee{
	{ID: "E001", Name: "Dr. Mohamed Benali", Email: "benali@chu-tlemcen.dz", DeviceIP: "127.0.0.31", Role: "doctor"},
	{ID: "E002", Name: "Dr. Karima Hadj", Email: "hadj@chu-tlemcen.dz", DeviceIP: "127.0.0.31", Role: "doctor"},
	{ID: "E003", Name: "Dr. Youssef Meziane", Email: "meziane@chu-tlemcen.dz", DeviceIP: "127.0.0.41", Role: "doctor"},
	{ID: "E004", Name: "Inf. Fatima Khelifi", Email: "khelifi@chu-tlemcen.dz", DeviceIP: "127.0.0.32", Role: "nurse"},
	{ID: "E005", Name: "Inf. Sara Boudiaf", Email: "boudiaf@chu-tlemcen.dz", DeviceIP: "127.0.0.32", Role: "nurse"},
	{ID: "E006", Name: "Inf. Amina Terki", Email: "terki@chu-tlemcen.dz", DeviceIP: "127.0.0.32", Role: "nurse"},
	{ID: "E007", Name: "Admin. Karim Mansouri", Email: "mansouri@chu-tlemcen.dz", DeviceIP: "127.0.0.30", Role: "admin"},
	{ID: "E008", Name: "Admin. Nadia Bensalem", Email: "bensalem@chu-tlemcen.dz", DeviceIP: "127.0.0.30", Role: "admin"},
	{ID: "E009", Name: "Fact. Omar Zerrouki", Email: "zerrouki@chu-tlemcen.dz", DeviceIP: "127.0.0.33", Role: "billing"},
	{ID: "E010", Name: "Fact. Lynda Aouadi", Email: "aouadi@chu-tlemcen.dz", DeviceIP: "127.0.0.33", Role: "billing"},
}

func GenerateEmployeesFile(path string) error {
	data, err := json.MarshalIndent(simulatedEmployees, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return err
	}
	fmt.Printf("[*] Generated %s with %d simulated employees\n", path, len(simulatedEmployees))
	return nil
}
