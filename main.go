package main

// the types in this code need refactoring
import (
	"bytes"
	"crypto/ecdh"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"time"
	"web_cert_reporting_faultTolerantChainingZK_NonInteractive/auditor"
	"web_cert_reporting_faultTolerantChainingZK_NonInteractive/client"
	"web_cert_reporting_faultTolerantChainingZK_NonInteractive/safeprime"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

func main() {
	// general init
	args := os.Args[1:]
	curve := ecdh.P256()
	database_name := "database.json"
	zkdatabase_name := "zkdatabase.json"
	numClients, err := strconv.Atoi(args[0])
	secret_pieces := uint32(numClients - 1)
	threshold := uint32(8)
	clients_sit_out := 0
	number_of_shufflers := 1
	shuffle_keyset, err := strconv.Atoi(args[1])
	CertAuditor := auditor.NewAuditor(database_name, zkdatabase_name, curve, secret_pieces, threshold, curves.P256())
	CertAuditor.InitializeDatabase()
	fmt.Println("Auditer Initialized, Enter reporting phase")
	/// init client and starting the reporting phase
	clients := make([]*auditor.Client, numClients)
	clients_out := make([]*auditor.Client, clients_sit_out)
	for i := 0; i < numClients; i++ {
		clients[i] = client.NewClient(CertAuditor, i)
		// register shuffling key to the auditor
		client.RegisterShuffleKeyWithAduitor(clients[i], CertAuditor)
	}
	// shuffle client order to make sure that the protocol works
	// ShuffleClient(clients)

	fmt.Println("clients created")
	// Read the existing data from the database file
	existingData, err := auditor.ReadDatabase(CertAuditor)
	if err != nil {
		return
	}

	// Unmarshal the existing data into a slice of CipherText
	var database auditor.Database
	err = json.Unmarshal(existingData, &database)
	if err != nil {
		return
	}

	// Unmarshal the byte slice into variable
	zkdatabase := auditor.ZKDatabase{
		ZK_info: []*auditor.ZKRecords{},
	}

	CertAuditor.DatabaseR = &database
	CertAuditor.ZKDatabaseR = &zkdatabase
	// database.Shuffle_PubKeys
	fmt.Println("shufflers: ", len(database.Shuffle_PubKeys))
	oddprimes := safeprime.GeneratePrimesWithout2(1 << 15)
	p, q, p_prime, q_prime, err := safeprime.GenerateGroupSubgroup(160, 15, 140, oddprimes)
	for i := 0; i < numClients; i++ {
		entry, err := client.CreateInitialEntry(clients[i])
		if err != nil {
			fmt.Println(err)
			return
		}

		// elaspe := auditor.ReportPhase_AppendEntryToDatabase(CertAuditor, entry, numClients, p, q, p_prime, q_prime)

		//// client shares the secrete in a encrypted way
		// client.SecreteShare(CertAuditor, clients[i])
		if i == numClients/2+numClients/10 {
			elaspe := auditor.ReportPhase_AppendEntryToDatabase(CertAuditor, entry, numClients, p, q, p_prime, q_prime, true)
			fmt.Printf("submit took %v to execute. with %d clients, under %d keys\n", elaspe, numClients, shuffle_keyset)
			return
		} else {
			auditor.ReportPhase_AppendEntryToDatabase(CertAuditor, entry, numClients, p, q, p_prime, q_prime, false)
		}
	}
	// prepopulate the shuffers field so that all shufflers are fixed
	fmt.Println("Reporting phase complete, Enter shuffling phase")
	if serialized, err := json.Marshal(database); err == nil {
		const bytesPerGB = 1024 * 1024 * 1024
		fmt.Printf("database size: %.4f GB\n", float64(len(serialized))/float64(bytesPerGB))
		if err := os.WriteFile("database.json", serialized, 0o644); err != nil {
			fmt.Println("failed to write database to disk:", err)
		}
	} else {
		fmt.Println("failed to compute database size:", err)
	}
	//shuffling stage
	for i := 0; i < number_of_shufflers; i++ {
		////***** preparing for zk proof
		err := CertAuditor.PopulateZKInfo(clients[i], &database, &zkdatabase)
		if err != nil {
			fmt.Println(err)
			panic("Error in populating ZK info, this is bad")
		}
		////***** end of preparing for zk proof
		// start := time.Now() // Start the timer
		t := client.ClientShuffle(CertAuditor, clients[i], shuffle_keyset, number_of_shufflers)
		// elapsed := time.Since(start) // Calculate elapsed time
		fmt.Printf("Sequential Shuffling took %v to execute. with %d clients, under %d keys\n", t, numClients, shuffle_keyset)
		return
	}

	fmt.Println("Shuffling Complete, Enter Reveal Client Phase")
	// fmt.Println("Making a copy of the shuffled database")
	// auditor.MakeACopyOfDatabase(CertAuditor)
	// fmt.Println("Done!")
	// fmt.Println("Fault Tolerant, Randomly picking clients that will not participate")
	// for i := 0; i < clients_sit_out; i++ {
	// 	// picking clients to sit out
	// 	clients_out[i], clients = removeRandomElement(clients)
	// }

	fmt.Println(len(clients))
	for i := 0; i < 1; i++ {
		start := time.Now()
		client.ClientReveal(CertAuditor, clients[i])
		elapsed := time.Since(start).Seconds()
		fmt.Printf("One reveal took %v to execute. with %d clients, under %d keys\n", elapsed, numClients, shuffle_keyset)
		// err := auditor.WriteRevealInfoToDatabase(CertAuditor, db)
		fmt.Println("One Client Reveal Complete, Auditor Calculating the entries")
		return
	}

	result := auditor.CalculateEntries(CertAuditor)
	// fmt.Println(result)
	if clients_sit_out > 0 {
		// fault tolerance kick in
		fmt.Println("Fault Tolerant Kicking in")
		for i := 0; i < len(clients_out); i++ {
			fault_tolerant_results := []*auditor.SecreteShareDecrypt{}
			// client reports the pieces to the auditor to decrypt
			for j := 0; j < len(clients); j++ {
				decrypted_piece, err := client.ClientReportDecryptedSecret(CertAuditor, clients[j], clients_out[i].ID)
				if err == nil && decrypted_piece != nil {
					fault_tolerant_results = append(fault_tolerant_results, decrypted_piece)
				}
			}
			// may need to check whether the client number required passed the threshold
			//compute the new result after this round of fault tolerance
			var err error
			result, err = auditor.CalculateEntriesForFaultToleranceOfOneClient(CertAuditor, result, fault_tolerant_results)
			if err != nil {
				fmt.Println(err)
				return
			}
		}
	}
	// fmt.Println(result)
	successful := true
	fmt.Println("Results calculated, verifying the correctness of the entries")
	for i := 0; i < len(clients); i++ {
		fmt.Print("checking for client ")
		fmt.Print(clients[i].ID)
		fmt.Println(": ")
		// fmt.Print("Intended Reporting value is")
		// fmt.Println(clients[i].ReportingValue)
		fmt.Println("Finding the entry in the auditor logs")
		successful_one_client := false
		for j := 0; j < len(result); j++ {
			extracted_cert, _ := client.ExtractData(result[j])
			// if err != nil {
			// 	fmt.Println(err)
			// 	continue
			// }
			if bytes.Equal(extracted_cert, clients[i].ReportingValue) {
				fmt.Print("Found Matching Entry! At index ")
				fmt.Println(j)
				fmt.Println("Verifying the hashes for the entry")
				err := client.VerifyHash(result[j])
				if err != nil {
					fmt.Println(err)
					fmt.Println("Hash verification failed!")
					continue
				}
				fmt.Println("Hash verification passed!")
				successful_one_client = true
			}
		}
		if !successful_one_client {
			successful = false
		}
	}
	if successful {
		fmt.Println("Success! Every Clients' entries are reported and decrypted correctly")
	} else {
		fmt.Println("FAIL!")
	}
	successful1 := true
	fmt.Println("verifying the those who did not participate did not reveal their value")
	for i := 0; i < len(clients_out); i++ {
		fmt.Print("checking for client ")
		fmt.Print(clients_out[i].ID)
		fmt.Println(": ")
		// fmt.Print("Intended Reporting value is")
		// fmt.Println(clients[i].ReportingValue)
		fmt.Println("Finding the entry in the auditor logs")
		successful_one_client1 := true
		for j := 0; j < len(result); j++ {
			extracted_cert, _ := client.ExtractData(result[j])
			// if err != nil {
			// 	fmt.Print(err)
			// 	fmt.Print("client ")
			// 	fmt.Print(clients_out[i].ID)
			// 	fmt.Println("did not reveal their value, Good!")
			// 	// return
			// 	continue
			// }
			if bytes.Equal(extracted_cert, clients_out[i].ReportingValue) {
				fmt.Print("Found Matching Entry! At index Fail!!!!!")
				fmt.Println(j)
				successful_one_client1 = false
			}
		}
		fmt.Print("Did NOT FIND IT! GOOD for Client ")
		fmt.Println(clients_out[i].ID)
		if !successful_one_client1 {
			successful1 = false
		}
	}
	if successful && successful1 {
		fmt.Println("Success! Every Clients' entries are reported and decrypted correctly for participating client. Those who did not reveal did not get revealed")
	} else {
		fmt.Println("FAIL!")
	}
	fmt.Println("This is Fault Tolerant Version!")
}

func removeRandomElement(slice []*auditor.Client) (*auditor.Client, []*auditor.Client) {
	index := rand.Intn(len(slice))
	removed := slice[index]
	return removed, append(slice[:index], slice[index+1:]...)
}

func ShuffleClient(slice []*auditor.Client) {
	n := len(slice)
	for i := n - 1; i > 0; i-- {
		j := randomInt(i + 1)                   // Get a secure random index from 0 to i
		slice[i], slice[j] = slice[j], slice[i] // Swap the elements at indexes i and j
	}
}

// randomInt returns a secure random integer between 0 (inclusive) and n (exclusive).
func randomInt(n int) int {
	var buf [8]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		panic(err)
	}
	return int(binary.BigEndian.Uint64(buf[:]) % uint64(n))
}
