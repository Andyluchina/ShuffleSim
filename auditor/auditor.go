package auditor

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"
	"web_cert_reporting_faultTolerantChainingZK_NonInteractive/elgamal"
	"web_cert_reporting_faultTolerantChainingZK_NonInteractive/zklib"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/sharing"
)

type Client struct {
	ID             int
	ReportingKey   *ecdh.PrivateKey
	ShuffleKey     *ecdh.PrivateKey
	ReportingValue []byte
	Curve          ecdh.Curve
	G_report       []byte /// init point needs to be different for every client
	H_report       []byte
	G_shuffle      []byte /// init point needs to be different for every client
	H_shuffle      []byte
	DH_Pub_H       []byte /// pub key for secrete sharing
	DH_Pub_private []byte
	InitialG_ri0   []byte
}

// h = g^x where x is the private key
type ReportingEntry struct {
	Cert_times_h_r10 [][]byte
	// G_ri0            []byte
	H_r_i1    []byte
	G_ri1     []byte
	Shufflers [][]byte
}

type Database struct {
	Entries         []*ReportingEntry
	Shufflers_info  []*ShuffleRecords
	Decrypt_info    []*DecryptRecords
	Shuffle_PubKeys []*ShufflePubKeys
	SecreteShareMap map[int][]*SecreteSharePoint
	// ZK_info         []*ZKRecords
}

type ZKDatabase struct {
	ZK_info []*ZKRecords
}

type ZKRecords struct {
	ShufflerID      int
	EncryptionProof EcryptionProofRecord
	ShuffleProof    ShuffleProofRecord
	DecryptionProof DecryptionProofRecord
}

type DecryptionProofRecord struct {
	RG_X       [][]byte
	RG_Y       [][]byte
	Challenges [][]byte
	Ss_X       [][]byte
	Ss_Y       [][]byte
}

type EcryptionProofRecord struct {
	X_originals [][]byte
	Y_originals [][]byte
	X_primes    [][]byte
	Y_primes    [][]byte
	I1s         [][]byte
	I2s         [][]byte
	Cs          [][]byte
	Z1s         [][]byte
	Z2s         [][]byte
	Z3s         [][]byte
}

type ShuffleProofRecord struct {
	// recorded before shuffle
	EntriesBeforeShuffle [][][]byte
	// RSA public params
	RSA_P                   *big.Int
	RSA_Q                   *big.Int
	RSA_subgroup_p_prime    *big.Int
	RSA_subgroup_q_prime    *big.Int
	RSA_subgroup_generators []*big.Int
	// commitment
	EntriesAfterShuffle                    [][][]byte
	X_primes_encrypted_and_permutated_tagX [][]byte
	Y_primes_encrypted_and_permutated_tagY [][]byte
	Commitments                            []*big.Int
	Big_Vs                                 [][]byte
	V_prime_X                              []byte
	V_prime_Y                              []byte
	Updated_Shufflers_info                 []*ShuffleRecords
	//challenges
	ChanllengesLambda [][]byte
	// Responses
	Fs      []*big.Int
	SmallZ  *big.Int
	Z_ks    [][]byte
	Z_prime *big.Int
}

type ShuffleRecords struct {
	ID int
	// H_i []byte
	// G_i []byte
}

type SecreteSharePoint struct {
	Intended_Client int
	Tag             uint32
	Encrypted_y     []byte
}

type ShufflePubKeys struct {
	ID       int
	H_i      []byte
	G_i      []byte
	DH_Pub_H []byte
}

type DecryptRecords struct {
	ShufflerID int
	Keys       [][]byte
}

type Auditor struct {
	FileName         string
	ZKFileName       string
	Curve            ecdh.Curve
	Shamir_pieces    uint32
	Shamir_threshold uint32
	Shamir_curve     *curves.Curve
	DatabaseR        *Database
	ZKDatabaseR      *ZKDatabase
}

type SecreteShareDecrypt struct {
	Tag           uint32
	DecryptPieces [][]byte
}

// NewAuditor creates a new Auditor instance
func NewAuditor(fileName string, zkfileName string, c ecdh.Curve, shamir_p uint32, shamir_t uint32, shamir_curve *curves.Curve) *Auditor {
	return &Auditor{FileName: fileName, ZKFileName: zkfileName, Curve: c, Shamir_pieces: shamir_p, Shamir_threshold: shamir_t, Shamir_curve: shamir_curve}
}

func (a *Auditor) InitializeDatabase() error {
	// Check if the file already exists.
	_, err := os.Stat(a.FileName)

	if err == nil {
		// File exists, clear its contents
		err = os.Truncate(a.FileName, 0)
		if err != nil {
			return err
		}
		fmt.Printf("Cleared contents of %s\n", a.FileName)
	} else if os.IsNotExist(err) {
		// File doesn't exist, create it.
		file, err := os.Create(a.FileName)
		if err != nil {
			return err
		}
		defer file.Close()
		fmt.Printf("Created %s\n", a.FileName)
	} else {
		return err
	}

	data, err := ReadDatabase(a)
	if err != nil {
		return err
	}

	// Unmarshal the byte slice into variable
	var database Database
	if len(data) > 0 {
		err = json.Unmarshal(data, &database)
		if err != nil {
			return err
		}
	} else {
		database = Database{
			Entries:         []*ReportingEntry{},
			Shufflers_info:  []*ShuffleRecords{},
			Decrypt_info:    []*DecryptRecords{},
			Shuffle_PubKeys: []*ShufflePubKeys{},
			SecreteShareMap: make(map[int][]*SecreteSharePoint),
		}
	}

	WriteRevealInfoToDatabase(a, &database)

	// zk do it again
	_, err = os.Stat(a.ZKFileName)

	// fmt.Println(a.ZKFileName)
	if err == nil {
		// File exists, clear its contents
		err = os.Truncate(a.ZKFileName, 0)
		if err != nil {
			return err
		}
		fmt.Printf("Cleared contents of %s\n", a.ZKFileName)
	} else if os.IsNotExist(err) {
		// File doesn't exist, create it.
		file, err := os.Create(a.ZKFileName)
		if err != nil {
			return err
		}
		defer file.Close()
		fmt.Printf("Created %s\n", a.ZKFileName)
	} else {
		return err
	}

	zkdata, err := ReadZKDatabase(a)
	if err != nil {
		return err
	}

	// Unmarshal the byte slice into variable
	var zkdatabase ZKDatabase
	if len(data) > 0 {
		err = json.Unmarshal(zkdata, &zkdatabase)
		if err != nil {
			return err
		}
	} else {
		zkdatabase = ZKDatabase{
			ZK_info: []*ZKRecords{},
		}
	}

	WriteZKInfoToZKDatabase(a, &zkdatabase)

	return nil
}

func ReadDatabase(certauditor *Auditor) ([]byte, error) {
	data, err := os.ReadFile(certauditor.FileName)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func ReadZKDatabase(certauditor *Auditor) ([]byte, error) {
	data, err := os.ReadFile(certauditor.ZKFileName)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func ClientGenerateChallengeShufflingProof_NonInteractive_Groth_And_Lu(
	orginal_entries [][][]byte,
	shuffled_entries [][][]byte,
	commitments []*big.Int,
	Big_Vs [][]byte,
	RSA_Q *big.Int,
	RSA_P *big.Int,
	RSA_subgroup_p_prime *big.Int,
	RSA_subgroup_q_prime *big.Int) [][]byte {
	// generate the challenges
	c := [][]byte{}
	for i := 0; i < len(orginal_entries); i++ {
		params1 := flattenBytes(orginal_entries[i])
		params5 := commitments[i]
		params9 := RSA_Q
		params10 := RSA_P
		params11 := RSA_subgroup_p_prime
		params12 := RSA_subgroup_q_prime

		combined := append([]byte{}, params1...)
		combined = append(combined, params5.Bytes()...)
		combined = append(combined, params9.Bytes()...)
		combined = append(combined, params10.Bytes()...)
		combined = append(combined, params11.Bytes()...)
		combined = append(combined, params12.Bytes()...)

		hasher := sha256.New()
		hasher.Write(combined)
		hash := hasher.Sum(nil)
		c = append(c, hash)
	}

	return c
}

func ReportPhase_AppendEntryToDatabase(certauditor *Auditor, entry *ReportingEntry, client_count int, p *big.Int, q *big.Int, q_prime *big.Int, p_prime *big.Int, real bool) float64 {
	// Read the existing data from the database file
	// existingData, err := ReadDatabase(certauditor)
	// if err != nil {
	// 	return err
	// }

	// // Unmarshal the existing data into a slice of CipherText
	// var database Database
	// err = json.Unmarshal(existingData, &database)
	// if err != nil {
	// 	return err
	// }

	if !real {

		database := certauditor.DatabaseR
		// fmt.Println("not real", len(database.Entries))
		// fill shufflers with point of zero
		for i := 0; i < client_count; i++ {
			entry.Shufflers = append(entry.Shufflers, elgamal.ReturnInfinityPoint())
		}
		database.Entries = append(database.Entries, entry)

		return 0
	}
	fmt.Println("Reaal real")
	database := certauditor.DatabaseR
	// fill shufflers with point of zero
	for i := 0; i < client_count; i++ {
		entry.Shufflers = append(entry.Shufflers, elgamal.ReturnInfinityPoint())
	}
	database.Entries = append(database.Entries, entry)

	original_entries := ExtractCertsFromEntries(database)
	registration_order := len(database.Entries)
	// reportingClient := database.Shuffle_PubKeys[registration_order-1]
	// find client's shuffling public key
	// init_client_pubkey := database.Shuffle_PubKeys[registration_order-1]

	permutationMatrix := zklib.GenerateIdentityMatrix(registration_order)
	inverse_permutationMatrix := permutationMatrix
	database.Shufflers_info = []*ShuffleRecords{}
	for i := 0; i < 1; i++ {
		// should just include everyone
		client_info := &ShuffleRecords{
			ID: registration_order,
		}
		database.Shufflers_info = append(database.Shufflers_info, client_info)
	}
	// encrypt all other entries under this public key
	R_l_k := make([][][]byte, len(database.Entries))
	// randomize the entries/ encrypt the entries
	for i := 0; i < len(database.Entries); i++ {
		rk := [][]byte{}
		for j := 0; j < len(database.Shufflers_info); j++ {
			shuffler_info := database.Shuffle_PubKeys[j]
			keys, err := LocatePublicKeyWithID(shuffler_info.ID, database.Shuffle_PubKeys)
			if err != nil {
				log.Fatalf("%v", err)
				return 0
			}
			r_i_prime := elgamal.Generate_Random_Dice_seed(certauditor.Curve)
			rk = append(rk, r_i_prime)
			g_r_i_prime, err := elgamal.ECDH_bytes(keys.G_i, r_i_prime)
			if err != nil {
				log.Fatalf("%v", err)
				return 0
			}
			/// changing the shuffler entry
			order := j
			database.Entries[i].Shufflers[order], err = elgamal.Encrypt(database.Entries[i].Shufflers[order], g_r_i_prime)
			if err != nil {
				log.Fatalf("%v", err)
				return 0
			}
			/// changing the msg entry
			h_r_i_prime, err := elgamal.ECDH_bytes(keys.H_i, r_i_prime)
			if err != nil {
				log.Fatalf("%v", err)
				return 0
			}
			database.Entries[i].Cert_times_h_r10, err = EncryptSegments(h_r_i_prime, database.Entries[i].Cert_times_h_r10)
			if err != nil {
				log.Fatalf("%v", err)
				return 0
			}
		}
		// }
		// rk = append(rk, r_i_k)
		R_l_k[i] = rk
	}

	start2 := time.Now()
	// // *********** doing zk proof for auditor encryption correctness ***********
	n := len(database.Entries) // matrix size
	l_t := 160
	l_s := 16 // a small security parameter

	N := new(big.Int).Mul(p, q)
	order_of_g := new(big.Int).Mul(p_prime, q_prime)
	l_r := order_of_g.BitLen() // the order of the unique subgroup can be huge so IDK what to put here

	l_s_plus_l_r := l_s + l_r

	gs := zklib.SampleNGenerators(p_prime, q_prime, n+2)

	// generating ds
	ds := make([]*big.Int, n)
	dj := big.NewInt(0)
	dn := big.NewInt(0)
	for i := 0; i < n; i++ {
		if i == n-1 {
			ds[i] = dn
		} else {
			d, _ := zklib.GenerateSecureRandomBits(l_t + 8)
			ds[i] = zklib.SetBigIntWithBytes(d)
			dn = new(big.Int).Add(dn, new(big.Int).Neg(ds[i]))
		}

		dj = new(big.Int).Add(dj, new(big.Int).Mul(ds[i], ds[i]))
	}

	// generate commitments
	commitments := make([]*big.Int, n+1)
	rs := make([]*big.Int, 0)
	for i := 0; i <= n; i++ {
		if i == n {
			new_r, err := zklib.GenerateSecureRandomBits(l_t + l_s_plus_l_r)
			if err != nil {
				panic(err)
			}
			commitments[i] = zklib.Generate_commitment(gs, ds, dj, new_r, N)
			rs = append(rs, zklib.SetBigIntWithBytes(new_r))
		} else {
			new_r, err := zklib.GenerateSecureRandomBits(l_r)
			if err != nil {
				panic(err)
			}
			backward_index, _ := zklib.BackwardMapping(i, permutationMatrix)
			d_needed := ds[backward_index]
			d_needed = new(big.Int).Mul(d_needed, big.NewInt(2))
			unitVector := zklib.UnitVector(n, inverse_permutationMatrix[i])
			commitments[i] = zklib.Generate_commitment(gs, zklib.IntToBigInt(unitVector), d_needed, new_r, N) // Fix: Add N as the last argument
			rs = append(rs, zklib.SetBigIntWithBytes(new_r))                                                  // Fix: Assign the result of append to rs
		}
	}

	shuffled_entries := ExtractCertsFromEntries(database)

	// generate the Big_V for the entries
	// we have one V for each segment of the entry
	Big_Vs := [][]byte{}
	// init the Vs
	for i := 0; i < len(database.Entries[0].Cert_times_h_r10); i++ {
		Big_Vs = append(Big_Vs, elgamal.ReturnZeroPoint())
	}
	// adding up the Ci_di
	for i := 0; i < n; i++ {
		for j := 0; j < len(database.Entries[0].Cert_times_h_r10); j++ {
			Ci_di, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(database.Entries[i].Cert_times_h_r10[j], ds[i].Bytes())
			if err != nil {
				panic(err)
			}
			if ds[i].Cmp(big.NewInt(0)) < 0 {
				// //("detected negative ds[i]")
				Ci_di, err = elgamal.ReturnNegative(Ci_di)
				if err != nil {
					panic(err)
				}
			}
			Big_Vs[j], err = elgamal.Encrypt(Big_Vs[j], Ci_di)
		}
	}

	// Bs are R_R in the paper
	// calculate all public keys
	Bs := [][]byte{}
	for i := 0; i < len(database.Shufflers_info); i++ {
		B, err := zklib.GenerateSecureRandomBits(l_s_plus_l_r + l_t)
		if err != nil {
			panic(err)
		}
		Bs = append(Bs, B)
	}
	for i := 0; i < len(database.Shufflers_info); i++ {
		for j := 0; j < len(database.Entries[0].Cert_times_h_r10); j++ {
			keys, err := LocatePublicKeyWithID(database.Shufflers_info[i].ID, database.Shuffle_PubKeys)
			if err != nil {
				log.Fatalf("%v", err)
				return 0
			}
			// add negative encryption with this public key
			Enc_B_pos, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(keys.H_i, Bs[i])
			Enc_B, err := elgamal.ReturnNegative(Enc_B_pos)
			if err != nil {
				log.Fatalf("%v", err)
				return 0
			}
			Big_Vs[j], err = elgamal.Encrypt(Big_Vs[j], Enc_B)
		}
	}

	// submit shuffled entries, tags(X_primes_encrypted_and_permutated, Y_primes_encrypted_and_permutated), commitments, and Vs to the auditor
	// auditor will in turn, generate the challenges
	lambdas := ClientGenerateChallengeShufflingProof_NonInteractive_Groth_And_Lu(
		original_entries, // original_entries [][][]byte,
		shuffled_entries, // 	shuffled_entries [][][]byte,
		commitments,      // commitments []*big.Int,
		Big_Vs,           // Big_Vs [][]byte,
		q,                // RSA_Q *big.Int,
		p,                // RSA_P *big.Int,
		p_prime,          // RSA_subgroup_p_prime *big.Int,
		q_prime)          // RSA_subgroup_q_prime *big.Int,
	// gs,                                // RSA_subgroup_generators []*big.Int,
	// )           // Updated_Shufflers_info []*ShuffleRecords

	// generate the replys
	fs := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		t_pi_j, _ := zklib.ForwardMapping(i, permutationMatrix)
		fs[i] = new(big.Int).Add(zklib.SetBigIntWithBytes(lambdas[t_pi_j]), ds[i])
	}

	small_z := big.NewInt(0)
	for i := 0; i < n; i++ {
		small_z = new(big.Int).Add(small_z, new(big.Int).Mul(zklib.SetBigIntWithBytes(lambdas[i]), rs[i]))
	}
	small_z = new(big.Int).Add(small_z, rs[n])

	/// generate Z_ks **** hard part
	Z_ks := [][]byte{}
	for k := 0; k < len(database.Shufflers_info); k++ {
		Z_k := zklib.SetBigIntWithBytes(Bs[k])
		for l := 0; l < n; l++ {
			R_l_k_one := zklib.SetBigIntWithBytes(R_l_k[l][k])
			pi_l, err := zklib.ForwardMapping(l, permutationMatrix)
			if err != nil {
				log.Fatalf("%v", err)
				return 0
			}
			lambda_pi_l_times_R_l_k := new(big.Int).Mul(zklib.SetBigIntWithBytes(lambdas[pi_l]), R_l_k_one)
			Z_k = new(big.Int).Add(Z_k, lambda_pi_l_times_R_l_k)
		}
		Z_ks = append(Z_ks, Z_k.Bytes())
	}

	elap := time.Since(start2).Seconds()

	return elap
}

func WriteRevealInfoToDatabase(certauditor *Auditor, db *Database) error {
	// Marshal the updated array back to a byte slice
	updatedData, err := json.Marshal(db)
	// fmt.Println(updatedData)
	if err != nil {
		return err
	}

	// Write the updated data to the file
	err = os.WriteFile(certauditor.FileName, updatedData, 0644)
	if err != nil {
		return err
	}

	return nil
}

func WriteZKInfoToZKDatabase(certauditor *Auditor, zkdb *ZKDatabase) error {
	// Marshal the updated array back to a byte slice
	updatedData, err := json.Marshal(zkdb)
	// fmt.Println(updatedData)
	if err != nil {
		return err
	}

	// Write the updated data to the file
	err = os.WriteFile(certauditor.ZKFileName, updatedData, 0644)
	if err != nil {
		return err
	}

	return nil
}

func CalculateEntries(certauditor *Auditor) [][][]byte {
	/// reading the database
	data, err := ReadDatabase(certauditor)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return nil
	}
	var database Database

	// Unmarshal the byte slice into variable
	err = json.Unmarshal(data, &database)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return nil
	}
	res := [][][]byte{}
	// decrypting
	for i := 0; i < len(database.Entries); i++ {
		res = append(res, database.Entries[i].Cert_times_h_r10)
		for j := 0; j < len(database.Decrypt_info); j++ {
			res[i], err = DecryptSegments(database.Decrypt_info[j].Keys[i], res[i])
			if err != nil {
				log.Fatalf("%v", err)
				return nil
			}
		}
	}
	return res
}

func DecryptSegments(SharedSecret []byte, segments [][]byte) ([][]byte, error) {
	// Decrypt the segments
	decryptedSegments := make([][]byte, len(segments))
	for i, segment := range segments {
		decryptedSegment, err := elgamal.Decrypt(SharedSecret, segment)
		if err != nil {
			return nil, err
		}
		decryptedSegments[i] = decryptedSegment
	}

	return decryptedSegments, nil
}

// func CalculateEntries_one_client(certauditor *Auditor, client *Client, database *Database) [][]byte {

// 	res := [][]byte{}
// 	// decrypting
// 	for i := 0; i < len(database.Entries); i++ {
// 		for j := 0; j < len(database.Decrypt_info); j++ {
// 			if database.Decrypt_info[j].ShufflerID == client.ID {
// 				res = append(res, database.Decrypt_info[j].Keys[i])
// 			}
// 		}
// 	}
// 	return res
// }

func MakeACopyOfDatabase(certauditor *Auditor) error {
	// / reading the database
	data, err := ReadDatabase(certauditor)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return nil
	}
	var database Database

	// Unmarshal the byte slice into variable
	err = json.Unmarshal(data, &database)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return nil
	}

	// Marshal the updated array back to a byte slice
	updatedData, err := json.Marshal(database)
	// fmt.Println(updatedData)
	if err != nil {
		return err
	}
	// Write the updated data to the file
	err = os.WriteFile("database_copy.json", updatedData, 0644)
	if err != nil {
		return err
	}

	return nil
}

func MakeACopyOfZKDatabase(certauditor *Auditor) error {
	// / reading the database
	data, err := ReadZKDatabase(certauditor)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return nil
	}
	var database ZKDatabase

	// Unmarshal the byte slice into variable
	err = json.Unmarshal(data, &database)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return nil
	}

	// Marshal the updated array back to a byte slice
	updatedData, err := json.Marshal(database)
	// fmt.Println(updatedData)
	if err != nil {
		return err
	}
	// Write the updated data to the file
	err = os.WriteFile("zkdatabase_copy.json", updatedData, 0644)
	if err != nil {
		return err
	}

	return nil
}

func CalculateEntriesForFaultToleranceOfOneClient(CertAuditor *Auditor, result [][][]byte, fault_tolerant_results []*SecreteShareDecrypt) ([][][]byte, error) {
	// the laranagian method, brutal
	// construct a map and a tag array to enable better access
	list_of_tags := make([]uint32, len(fault_tolerant_results))
	for i := 0; i < len(list_of_tags); i++ {
		// result[i]
		list_of_tags[i] = fault_tolerant_results[i].Tag
	}
	// fmt.Println(list_of_tags)
	// recreate the shamir and calculate coefficients
	scheme, _ := sharing.NewShamir(CertAuditor.Shamir_threshold, CertAuditor.Shamir_pieces, CertAuditor.Shamir_curve)
	lagrange_map, err := scheme.LagrangeCoeffs(list_of_tags)
	if err != nil {
		log.Fatalf("%v", err)
		return nil, err
	}
	// apply larangian to every entry
	// fmt.Println(lagrange_map)
	/// add up first
	calculated_res := [][]byte{}
	for i := 0; i < len(fault_tolerant_results); i++ {
		// result[i]
		lcoef := lagrange_map[fault_tolerant_results[i].Tag].Bytes()
		for j := 0; j < len(result); j++ {
			d_lambda, err := elgamal.ECDH_bytes(fault_tolerant_results[i].DecryptPieces[j], lcoef)
			if err != nil {
				log.Fatalf("%v", err)
				return nil, err
			}
			if i == 0 {
				calculated_res = append(calculated_res, d_lambda)
			} else {
				calculated_res[j], err = elgamal.Encrypt(calculated_res[j], d_lambda)
				if err != nil {
					log.Fatalf("%v", err)
					return nil, err
				}
			}
		}
	}
	for k := 0; k < len(result); k++ {
		result[k], _ = DecryptSegments(calculated_res[k], result[k])
	}
	return result, err
}

//// ZERO KNOWLEDGE PROOF ***********

// / func prepopulate the ZK info to keep a record
func (a *Auditor) PopulateZKInfo(shuffling_client *Client, database *Database, zkdatabase *ZKDatabase) error {

	/// prepopulate the encryption proof
	zkdatabase.ZK_info = append(zkdatabase.ZK_info, &ZKRecords{
		ShufflerID: shuffling_client.ID,
		EncryptionProof: EcryptionProofRecord{
			X_originals: ExtractH_r_i1sFromEntries(database),
			Y_originals: ExtractG_ri1sFromEntries(database),
			Z1s:         [][]byte{},
			Z2s:         [][]byte{},
			Z3s:         [][]byte{},
			X_primes:    [][]byte{},
			Y_primes:    [][]byte{},
			I1s:         [][]byte{},
			I2s:         [][]byte{},
			Cs:          [][]byte{},
		},
		ShuffleProof: ShuffleProofRecord{
			EntriesBeforeShuffle:                   ExtractCertsFromEntries(database),
			EntriesAfterShuffle:                    [][][]byte{},
			X_primes_encrypted_and_permutated_tagX: [][]byte{},
			Y_primes_encrypted_and_permutated_tagY: [][]byte{},
			Commitments:                            []*big.Int{},
			Big_Vs:                                 [][]byte{},
			V_prime_X:                              []byte{},
			V_prime_Y:                              []byte{},
			ChanllengesLambda:                      [][]byte{},
			Fs:                                     []*big.Int{},
			SmallZ:                                 new(big.Int),
			Z_ks:                                   [][]byte{},
			Z_prime:                                new(big.Int),
			Updated_Shufflers_info:                 []*ShuffleRecords{},
		},
		DecryptionProof: DecryptionProofRecord{
			RG_X:       [][]byte{},
			RG_Y:       [][]byte{},
			Challenges: [][]byte{},
			Ss_X:       [][]byte{},
			Ss_Y:       [][]byte{},
		},
	})

	/// prepopulate the shuffle proof groth and Lu

	// Marshal the updated array back to a byte slice
	// updatedData, err := json.Marshal(zkdatabase)
	// // fmt.Println(updatedData)
	// if err != nil {
	// 	return err
	// }
	// // Write the updated data to the file
	// err = os.WriteFile(a.ZKFileName, updatedData, 0644)
	// if err != nil {
	// 	return err
	// }

	// MakeACopyOfZKDatabase(a)

	return nil
}

func ExtractEntriesFromEntries(database *Database) [][][]byte {
	res := [][][]byte{}
	for i := 0; i < len(database.Entries); i++ {
		res = append(res, database.Entries[i].Cert_times_h_r10)
	}
	return res
}

func ExtractH_r_i1sFromEntries(database *Database) [][]byte {
	res := [][]byte{}
	for i := 0; i < len(database.Entries); i++ {
		res = append(res, database.Entries[i].H_r_i1)
	}
	return res
}

func ExtractCertsFromEntries(database *Database) [][][]byte {
	res := [][][]byte{}
	for i := 0; i < len(database.Entries); i++ {
		res = append(res, database.Entries[i].Cert_times_h_r10)
	}
	return res
}

func ExtractG_ri1sFromEntries(database *Database) [][]byte {
	res := [][]byte{}
	for i := 0; i < len(database.Entries); i++ {
		res = append(res, database.Entries[i].G_ri1)

	}
	return res
}

func (a *Auditor) ZKEncryption_RecordAndVerifyResponses(proving_client *Client,
	z1s [][]byte,
	z2s [][]byte,
	z3s [][]byte,
	X_primes [][]byte,
	Y_primes [][]byte,
	I1s [][]byte,
	I2s [][]byte,
	cs [][]byte) bool {
	// / reading the zkdatabase
	zkdatabase := a.ZKDatabaseR

	// record the response
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.Z1s = z1s
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.Z2s = z2s
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.Z3s = z3s
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.X_primes = X_primes
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.Y_primes = Y_primes
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.I1s = I1s
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.I2s = I2s
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.Cs = cs
	// fmt.Println(z1s)
	// Marshal the updated array back to a byte slice
	// for i := 0; i < len(z1s); i++ {
	// 	// first challenge
	// 	X_z1, err := elgamal.ECDH_bytes(zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.X_originals[i], z1s[i])
	// 	if err != nil {
	// 		log.Fatalf("%v", err)
	// 		return false
	// 	}

	// 	H_z2, err := elgamal.ECDH_bytes(proving_client.H_shuffle, z2s[i])
	// 	if err != nil {
	// 		log.Fatalf("%v", err)
	// 		return false
	// 	}

	// 	first_challenge_left_hand, err := elgamal.Encrypt(X_z1, H_z2)
	// 	if err != nil {
	// 		log.Fatalf("%v", err)
	// 		return false
	// 	}

	// 	X_prime_c, err := elgamal.ECDH_bytes(zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.X_primes[i], zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.Cs[i])
	// 	if err != nil {
	// 		log.Fatalf("%v", err)
	// 		return false
	// 	}
	// 	first_challenge_right_hand, err := elgamal.Encrypt(X_prime_c, zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.I1s[i])
	// 	if err != nil {
	// 		log.Fatalf("%v", err)
	// 		return false
	// 	}

	// 	if !bytes.Equal(first_challenge_left_hand, first_challenge_right_hand) {
	// 		fmt.Println("First challenge failed for client", proving_client.ID)
	// 		return false
	// 	}
	// 	// else {
	// 	// 	fmt.Println("First challenge PASSED for client", proving_client.ID)
	// 	// }

	// 	// second challenge
	// 	Y_z1, err := elgamal.ECDH_bytes(zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.Y_originals[i], z1s[i])
	// 	if err != nil {
	// 		log.Fatalf("%v", err)
	// 		return false
	// 	}

	// 	H_z3, err := elgamal.ECDH_bytes(proving_client.H_shuffle, z3s[i])
	// 	if err != nil {
	// 		log.Fatalf("%v", err)
	// 		return false
	// 	}

	// 	second_challenge_left_hand, err := elgamal.Encrypt(Y_z1, H_z3)
	// 	if err != nil {
	// 		log.Fatalf("%v", err)
	// 		return false
	// 	}

	// 	Y_prime_c, err := elgamal.ECDH_bytes(zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.Y_primes[i], zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.Cs[i])
	// 	if err != nil {
	// 		log.Fatalf("%v", err)
	// 		return false
	// 	}
	// 	second_challenge_right_hand, err := elgamal.Encrypt(Y_prime_c, zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.I2s[i])
	// 	if err != nil {
	// 		log.Fatalf("%v", err)
	// 		return false
	// 	}

	// 	if !bytes.Equal(second_challenge_left_hand, second_challenge_right_hand) {
	// 		fmt.Println("Second challenge failed for client", proving_client.ID)
	// 		return false
	// 	}
	// 	// else {
	// 	// 	fmt.Println("Second challenge PASSED for client", proving_client.ID)
	// 	// }

	// }

	// fmt.Println("ZK Proof for encryption is verified for client ", proving_client.ID)
	return true
}

func (a *Auditor) ZKDecryption_RecordAndVerifyResponses(
	rG_x [][]byte,
	rG_y [][]byte,
	Challenges [][]byte,
	S_x [][]byte,
	S_y [][]byte) (bool, error) {
	// / reading the zkdatabase
	zkdatabase := a.ZKDatabaseR

	// database := a.DatabaseR

	// record the response
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].DecryptionProof.RG_X = rG_x
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].DecryptionProof.RG_Y = rG_y
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].DecryptionProof.Challenges = Challenges
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].DecryptionProof.Ss_X = S_x
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].DecryptionProof.Ss_Y = S_y

	// checks sG=rG+cH
	// proving_client := zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShufflerID
	// pubkeys_client, err := LocatePublicKeyWithID(proving_client, database.Shuffle_PubKeys)

	// if err != nil {
	// 	log.Fatalf("%v", err)
	// 	return false, err
	// }

	// // fmt.Println(S_x)

	// for i := 0; i < len(S_x); i++ {
	// 	// sG
	// 	sG, err := elgamal.ECDH_bytes(pubkeys_client.G_i, S_x[i])
	// 	if err != nil {
	// 		log.Fatalf("%v", err)
	// 		return false, err
	// 	}

	// 	// rG
	// 	rG := zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].DecryptionProof.RG_X[i]

	// 	// cH
	// 	cH, err := elgamal.ECDH_bytes(pubkeys_client.H_i, zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].DecryptionProof.Challenges[i])
	// 	if err != nil {
	// 		log.Fatalf("%v", err)
	// 		return false, err
	// 	}

	// 	right_hand, err := elgamal.Encrypt(rG, cH)
	// 	if err != nil {
	// 		log.Fatalf("%v", err)
	// 		return false, err
	// 	}

	// 	// sG=rG+cH
	// 	if !bytes.Equal(sG, right_hand) {
	// 		fmt.Println("Decryption Proof failed for client", proving_client)
	// 		return false, nil
	// 	}
	// }

	return true, nil

}

// RSA_Q                                  *big.Int
// RSA_P                                  *big.Int
// RSA_subgroup_p_prime                   *big.Int
// RSA_subgroup_q_prime                   *big.Int
// RSA_subgroup_generators                []*big.Int

func (a *Auditor) ZKShuffling_RecordAndVerifyResponses(
	shuffled_entries [][][]byte,
	X_primes_encrypted_and_permutated [][]byte,
	Y_primes_encrypted_and_permutated [][]byte,
	commitments []*big.Int,
	Big_Vs [][]byte,
	V_prime_X []byte,
	V_prime_Y []byte,
	ChanllengesLambda [][]byte,
	RSA_Q *big.Int,
	RSA_P *big.Int,
	p_prime *big.Int,
	q_prime *big.Int,
	RSA_subgroup_generators []*big.Int,
	Updated_Shufflers_info []*ShuffleRecords,
	fs []*big.Int,
	small_z *big.Int,
	Z_ks [][]byte,
	Z_prime *big.Int) (bool, error) {
	// read zk database
	zkdatabase := a.ZKDatabaseR

	// database := a.DatabaseR

	// record the responses
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.EntriesAfterShuffle = shuffled_entries
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.X_primes_encrypted_and_permutated_tagX = X_primes_encrypted_and_permutated
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.Y_primes_encrypted_and_permutated_tagY = Y_primes_encrypted_and_permutated
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.Commitments = commitments
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.Big_Vs = Big_Vs
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.V_prime_X = V_prime_X
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.V_prime_Y = V_prime_Y
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.ChanllengesLambda = ChanllengesLambda
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.RSA_Q = RSA_Q
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.RSA_P = RSA_P
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.RSA_subgroup_p_prime = p_prime
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.RSA_subgroup_q_prime = q_prime
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.RSA_subgroup_generators = RSA_subgroup_generators
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.Updated_Shufflers_info = Updated_Shufflers_info
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.Fs = fs
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.SmallZ = small_z
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.Z_prime = Z_prime
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.Z_ks = Z_ks

	// n := len(zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.EntriesAfterShuffle)
	// gs := zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.RSA_subgroup_generators
	// N := new(big.Int).Mul(zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.RSA_P, zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.RSA_Q)
	// // first check
	// ts := zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.ChanllengesLambda
	// /// sum up fs and check if it is equal to sum of ts
	// sum := big.NewInt(0)
	// for _, f := range fs {
	// 	sum.Add(sum, f)
	// }
	// sum_ts := big.NewInt(0)
	// for _, t := range ts {
	// 	sum_ts.Add(sum_ts, zklib.SetBigIntWithBytes(t))
	// }
	// // fmt.Println("Sum of fs:", sum)
	// // fmt.Println("Sum of ts:", sum_ts)
	// if sum.Cmp(sum_ts) == 0 {
	// 	fmt.Println("First Test PASSED!!!!!!!!!Sum of fs is equal to sum of ts")
	// } else {
	// 	fmt.Println("Sum of fs is not equal to sum of ts")
	// 	return false, nil
	// }

	// // second check
	// // calculate f_delta
	// f_delta := big.NewInt(0)
	// // sum of f squared
	// for _, f := range fs {
	// 	f_delta.Add(f_delta, new(big.Int).Mul(f, f))
	// }
	// // minus sum of ts squared
	// for _, t := range ts {
	// 	f_delta.Sub(f_delta, new(big.Int).Mul(zklib.SetBigIntWithBytes(t), zklib.SetBigIntWithBytes(t)))
	// }

	// /// conducting second check
	// second_condition_right_hand_side := zklib.Generate_commitment(gs, fs, f_delta, small_z.Bytes(), N)
	// // fmt.Print("second_condition_right_hand_side ")
	// // fmt.Println(second_condition_right_hand_side)
	// second_condition_left_hand_side := new(big.Int).Set(zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.Commitments[n])
	// for i := 0; i < n; i++ {
	// 	second_condition_left_hand_side = new(big.Int).Mul(second_condition_left_hand_side, new(big.Int).Exp(zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.Commitments[i], zklib.SetBigIntWithBytes(ts[i]), N))
	// }
	// second_condition_left_hand_side = new(big.Int).Mod(second_condition_left_hand_side, N)

	// // fmt.Print("second_condition_left_hand_side ")
	// // fmt.Println(second_condition_left_hand_side)
	// // compare the two sides
	// if second_condition_left_hand_side.Cmp(second_condition_right_hand_side) == 0 {
	// 	fmt.Println("Second Test PASSED!!!!!!!!!")
	// } else {
	// 	fmt.Println("they are not equal! Failed???????")
	// 	return false, nil
	// }

	// // third check for the entries **** hardest part brutal
	// // k means the index for individual pieces of the entry
	// for k := 0; k < len(zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.EntriesAfterShuffle[0]); k++ {
	// 	third_check_left_hand_side := elgamal.ReturnInfinityPoint()
	// 	for i := 0; i < n; i++ {
	// 		C_i := zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.EntriesAfterShuffle[i][k]
	// 		C_i_f_i, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(C_i, fs[i].Bytes())
	// 		if err != nil {
	// 			panic(err)
	// 		}
	// 		// check if fs[i] is negative
	// 		if fs[i].Cmp(big.NewInt(0)) < 0 {
	// 			// fmt.Println("detected negative fs[i]")
	// 			C_i_f_i, err = elgamal.ReturnNegative(C_i_f_i)
	// 			if err != nil {
	// 				panic(err)
	// 			}
	// 		}
	// 		third_check_left_hand_side, err = elgamal.Encrypt(third_check_left_hand_side, C_i_f_i)
	// 		if err != nil {
	// 			panic(err)
	// 		}
	// 	}

	// 	third_check_right_hand_side := zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.Big_Vs[k]
	// 	for i := 0; i < n; i++ {
	// 		c_i := zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.EntriesBeforeShuffle[i][k]
	// 		c_i_lambda_i, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(c_i, ts[i])
	// 		if err != nil {
	// 			panic(err)
	// 		}
	// 		third_check_right_hand_side, err = elgamal.Encrypt(third_check_right_hand_side, c_i_lambda_i)
	// 	}
	// 	// find the public key of the shuffler
	// 	// log.Println(len(zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.Updated_Shufflers_info))
	// 	for i := 0; i < len(zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.Updated_Shufflers_info); i++ {
	// 		updated_shufflers := zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.Updated_Shufflers_info[i]
	// 		shuffler_keys, err := LocatePublicKeyWithID(updated_shufflers.ID, database.Shuffle_PubKeys)
	// 		if err != nil {
	// 			panic(err)
	// 		}
	// 		encrypted_one_with_Z_k, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(shuffler_keys.H_i, Z_ks[i])
	// 		if err != nil {
	// 			panic(err)
	// 		}
	// 		third_check_right_hand_side, err = elgamal.Encrypt(third_check_right_hand_side, encrypted_one_with_Z_k)
	// 		if err != nil {
	// 			panic(err)
	// 		}
	// 	}

	// 	// compare the two sides
	// 	if !bytes.Equal(third_check_left_hand_side, third_check_right_hand_side) {
	// 		fmt.Println("Third Test FAILED????????", k)
	// 		return false, nil
	// 	}
	// }
	// fmt.Println("Third Test concerning the cyphertext shuffling PASSED!!!!!!!!!")

	// var err error
	// // fourth check for tag X
	// fourth_condition_left_hand_side := elgamal.ReturnInfinityPoint()
	// if err != nil {
	// 	panic(err)
	// }
	// for i := 0; i < n; i++ {
	// 	T_i_f_i, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.X_primes_encrypted_and_permutated_tagX[i], fs[i].Bytes())
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	// check if fs[i] is negative
	// 	if fs[i].Cmp(big.NewInt(0)) < 0 {
	// 		// fmt.Println("detected negative fs[i]")
	// 		T_i_f_i, err = elgamal.ReturnNegative(T_i_f_i)
	// 		if err != nil {
	// 			panic(err)
	// 		}
	// 	}
	// 	fourth_condition_left_hand_side, err = elgamal.Encrypt(fourth_condition_left_hand_side, T_i_f_i)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// }
	// fourth_condition_right_hand_side := zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.V_prime_X
	// // find the public key of the shuffler
	// shuffler_keys, err := LocatePublicKeyWithID(zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShufflerID, database.Shuffle_PubKeys)
	// if err != nil {
	// 	panic(err)
	// }
	// encrypted_one_with_Z_prime, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(shuffler_keys.H_i, Z_prime.Bytes())
	// // fmt.Println(shuffler_keys.H_i)
	// if err != nil {
	// 	panic(err)
	// }
	// fourth_condition_right_hand_side, err = elgamal.Encrypt(fourth_condition_right_hand_side, encrypted_one_with_Z_prime)
	// if err != nil {
	// 	panic(err)
	// }
	// lambdas := ts
	// tags_before_shuffle := zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.X_primes
	// for i := 0; i < n; i++ {
	// 	small_c_i_lambda_i, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(tags_before_shuffle[i], lambdas[i])
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	fourth_condition_right_hand_side, err = elgamal.Encrypt(fourth_condition_right_hand_side, small_c_i_lambda_i)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// }
	// // compare the two sides
	// if bytes.Equal(fourth_condition_left_hand_side, fourth_condition_right_hand_side) {
	// 	fmt.Println("Fourth Test PASSED!!!!!!!!!")
	// } else {
	// 	fmt.Println("Fourth Test FAILED????????")
	// 	return false, nil
	// }

	// // fitfh check for tag Y
	// fifth_condition_left_hand_side := elgamal.ReturnInfinityPoint()
	// if err != nil {
	// 	panic(err)
	// }
	// for i := 0; i < n; i++ {
	// 	T_i_f_i, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.Y_primes_encrypted_and_permutated_tagY[i], fs[i].Bytes())
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	// check if fs[i] is negative
	// 	if fs[i].Cmp(big.NewInt(0)) < 0 {
	// 		// fmt.Println("detected negative fs[i]")
	// 		T_i_f_i, err = elgamal.ReturnNegative(T_i_f_i)
	// 		if err != nil {
	// 			panic(err)
	// 		}
	// 	}
	// 	fifth_condition_left_hand_side, err = elgamal.Encrypt(fifth_condition_left_hand_side, T_i_f_i)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// }
	// fifth_condition_right_hand_side := zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.V_prime_Y

	// fifth_condition_right_hand_side, err = elgamal.Encrypt(fifth_condition_right_hand_side, encrypted_one_with_Z_prime)
	// if err != nil {
	// 	panic(err)
	// }
	// // lambdas := ts
	// tags_before_shuffle_Y := zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.Y_primes
	// for i := 0; i < n; i++ {
	// 	small_C_i_lambda_i, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(tags_before_shuffle_Y[i], lambdas[i])
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	fifth_condition_right_hand_side, err = elgamal.Encrypt(fifth_condition_right_hand_side, small_C_i_lambda_i)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// }
	// // compare the two sides
	// if bytes.Equal(fifth_condition_left_hand_side, fifth_condition_right_hand_side) {
	// 	fmt.Println("Fifth Test PASSED!!!!!!!!!")
	// } else {
	// 	fmt.Println("Fifth Test FAILED????????")
	// 	return false, nil
	// }

	return true, nil

}

func LocatePublicKeyWithID(clientID int, ShufflerPublicKeys []*ShufflePubKeys) (*ShufflePubKeys, error) {
	for i := 0; i < len(ShufflerPublicKeys); i++ {
		if clientID == ShufflerPublicKeys[i].ID {
			return ShufflerPublicKeys[i], nil
		}
	}
	return nil, errors.New("Shuffler Public Key Not Found")
}

func EncryptSegments(h []byte, segments [][]byte) ([][]byte, error) {
	encrypted_segments := make([][]byte, len(segments))
	for i := 0; i < len(segments); i++ {
		encrypted, err := elgamal.Encrypt(h, segments[i])
		if err != nil {
			return nil, err
		}
		encrypted_segments[i] = encrypted
	}
	return encrypted_segments, nil
}

// flattenBytes takes a 2D slice of bytes and flattens it into a 1D slice.
func flattenBytes(twoD [][]byte) []byte {
	var oneD []byte
	for _, slice := range twoD {
		// Append each sub-slice to the new slice.
		oneD = append(oneD, slice...)
	}
	return oneD
}
