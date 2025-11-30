package zklib

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// setBigIntWithBytes sets a big.Int value using a slice of bytes and returns the big.Int.
func SetBigIntWithBytes(b []byte) *big.Int {
	var num big.Int
	num.SetBytes(b) // Interpret b as a big-endian unsigned integer
	return &num
}

func IntToBigInt(n []int) []*big.Int {
	bigInts := make([]*big.Int, len(n))
	for i, val := range n {
		bigInts[i] = big.NewInt(int64(val))
	}
	return bigInts
}

func GenerateIdentityMatrix(n int) []int {
	if n <= 0 {
		return nil
	}

	identity := make([]int, n)
	for i := range identity {
		identity[i] = i
	}

	return identity
}

// GeneratePermutation returns a permutation of size n using cryptographically secure randomness.
func GeneratePermutation(n int) []int {
	return securePerm(n)
}

// securePerm generates a cryptographically secure permutation of n integers.
func securePerm(n int) []int {
	perm := make([]int, n)
	for i := 0; i < n; i++ {
		perm[i] = i
	}

	for i := 1; i < n; i++ {
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		perm[i], perm[j.Int64()] = perm[j.Int64()], perm[i]
	}

	return perm
}

// printMatrix prints the matrix.
func PrintMatrix(matrix [][]int) {
	for _, row := range matrix {
		for _, val := range row {
			fmt.Printf("%d ", val)
		}
		fmt.Println()
	}
}

// InversePermutation computes the inverse permutation represented as an index slice.
func InversePermutation(perm []int) ([]int, error) {
	n := len(perm)
	inverse := make([]int, n)
	seen := make([]bool, n)
	for i, v := range perm {
		if v < 0 || v >= n {
			return nil, fmt.Errorf("permutation value out of range")
		}
		if seen[v] {
			return nil, fmt.Errorf("duplicate permutation value")
		}
		inverse[v] = i
		seen[v] = true
	}
	return inverse, nil
}

// ForwardMapping returns the original index mapped to the provided position.
func ForwardMapping(index int, perm []int) (int, error) {
	if index < 0 || index >= len(perm) {
		return -1, fmt.Errorf("index out of range")
	}
	return perm[index], nil
}

// BackwardMapping returns the permuted position for the provided original index.
func BackwardMapping(index int, inversePerm []int) (int, error) {
	if index < 0 || index >= len(inversePerm) {
		return -1, fmt.Errorf("index out of range")
	}
	return inversePerm[index], nil
}

// UnitVector returns a one-hot vector of the given length with 1 at index.
func UnitVector(length, index int) []int {
	vec := make([]int, length)
	if index >= 0 && index < length {
		vec[index] = 1
	}
	return vec
}

func isGenerator(g *big.Int, p *big.Int, q *big.Int) bool {
	group_order := new(big.Int).Mul(p, q)
	if !isCoprime(g, group_order) {
		return false
	}
	if new(big.Int).Exp(g, q, group_order).Cmp(big.NewInt(1)) != 0 && new(big.Int).Exp(g, p, group_order).Cmp(big.NewInt(1)) != 0 {
		return true
	}
	return false
}

// randomBigInt samples a random big.Int in the interval [a, b].
func randomBigInt(a, b *big.Int) (*big.Int, error) {
	// Ensure a <= b
	if a.Cmp(b) > 0 {
		return nil, fmt.Errorf("invalid interval: a must be less than or equal to b")
	}

	// Calculate the difference d = b - a
	d := new(big.Int).Sub(b, a)

	// Generate a random big.Int, r, in the interval [0, d]
	r, err := rand.Int(rand.Reader, new(big.Int).Add(d, big.NewInt(1))) // rand.Int samples in [0, n), so we add 1 to include b
	if err != nil {
		return nil, err
	}

	// Shift r to the interval [a, b] by adding a, resulting in a + r
	return r.Add(r, a), nil
}

func sampleAGenerator(p *big.Int, q *big.Int) *big.Int {
	for {
		g, err := randomBigInt(big.NewInt(2), new(big.Int).Mul(p, q))
		if err != nil {
			return nil
		}
		if isGenerator(g, p, q) {
			return g
		}
	}
}

func SampleNGenerators(p *big.Int, q *big.Int, g_needed int) []*big.Int {
	generators := make([]*big.Int, 0) // Fix: Change the type of generator to []*big.Int
	for i := 0; i < g_needed; i++ {
		generator := sampleAGenerator(p, q)
		generators = append(generators, generator) // Fix: Change the append statement to append a pointer to the generator slice
	}
	return generators // Fix: Change the return statement to return generator instead of &generator
}

func Generate_commitment(gs []*big.Int, ms []*big.Int, d_needed *big.Int, r []byte, N *big.Int) *big.Int {
	r_int := SetBigIntWithBytes(r)
	commitment := big.NewInt(1)
	for j := 0; j < len(ms); j++ {
		m := ms[j]
		commitment = new(big.Int).Mul(commitment, new(big.Int).Exp(gs[j], m, N)) // Fix: Add m as the second argument to Mul
	}
	commitment = new(big.Int).Mul(commitment, new(big.Int).Exp(gs[len(ms)], d_needed, N))
	commitment = new(big.Int).Mul(commitment, new(big.Int).Exp(gs[len(ms)+1], r_int, N))
	commitment = new(big.Int).Mod(commitment, N)
	return commitment // Fix: Add return statement
}

// isCoprime uses the Euclidean algorithm to check if a and b are coprime.
func isCoprime(a, b *big.Int) bool {
	return new(big.Int).GCD(nil, nil, a, b).Cmp(big.NewInt(1)) == 0
}

// GenerateSecureRandomBits generates a slice of bytes of the specified bit length.
// Note: The bit length n must be divisible by 8, as it returns a slice of bytes.
func GenerateSecureRandomBits(n int) ([]byte, error) {
	if n%8 != 0 {
		return nil, fmt.Errorf("bit length must be divisible by 8")
	}
	numOfBytes := n / 8
	b := make([]byte, numOfBytes)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
