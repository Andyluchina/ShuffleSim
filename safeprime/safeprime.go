package safeprime

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// Sieve of Eratosthenes algorithm to generate all primes less than max
func generatePrimes(max int) []*big.Int {
	sieve := make([]bool, max+1)
	for i := range sieve {
		sieve[i] = true
	}
	sieve[0], sieve[1] = false, false

	for p := 2; p*p <= max; p++ {
		if sieve[p] {
			for i := p * p; i <= max; i += p {
				sieve[i] = false
			}
		}
	}

	primes := make([]*big.Int, 0)
	for p := 2; p <= max; p++ {
		if sieve[p] {
			primes = append(primes, big.NewInt(int64(p)))
		}
	}

	return primes
}

// Sieve of Eratosthenes algorithm to generate all primes less than max
func GeneratePrimesWithout2(max int) []*big.Int {
	sieve := make([]bool, max+1)
	for i := range sieve {
		sieve[i] = true
	}
	sieve[0], sieve[1] = false, false

	for p := 2; p*p <= max; p++ {
		if sieve[p] {
			for i := p * p; i <= max; i += p {
				sieve[i] = false
			}
		}
	}

	primes := make([]*big.Int, 0)
	for p := 3; p <= max; p++ {
		if sieve[p] {
			primes = append(primes, big.NewInt(int64(p)))
		}
	}

	return primes
}

// Shuffle using crypto/rand for secure random number generation
func shufflePrimes(primes []*big.Int) {
	for i := len(primes) - 1; i > 0; i-- {
		nBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			panic(err) // Rand should never fail
		}
		j := int(nBig.Int64())

		primes[i], primes[j] = primes[j], primes[i]
	}
}

// Generate t distinct odd primes less than max using crypto/rand
func GenerateDistinctOddPrimes(t, max int, oddPrimes []*big.Int) ([]*big.Int, error) {
	if max <= 2 {
		return nil, fmt.Errorf("max must be greater than 2")
	}

	// oddPrimes are the Generate all primes less than max
	// fmt.Println("oddPrimes: ", len(oddPrimes))
	if len(oddPrimes) < t {
		return nil, fmt.Errorf("not enough primes: requested %d, but only %d available", t, len(oddPrimes))
	}

	// Shuffle the slice of odd primes using crypto/rand
	shufflePrimes(oddPrimes)

	// Select the first t odd primes
	selectedPrimes := oddPrimes[:t]

	return selectedPrimes, nil
}

func generateAPrime(l int) (*big.Int, error) {
	p, err := rand.Prime(rand.Reader, l)
	if err != nil {
		panic(err)
	}
	return p, nil
}

func calculateBigPrime(prime_n *big.Int, ns []*big.Int) *big.Int {
	one := big.NewInt(1)
	// p = prime_n * n1 * n2 * ... * nt * 2 + 1
	p := big.NewInt(1)
	p.Mul(prime_n, p)
	for _, n := range ns {
		p.Mul(p, n)
	}
	p.Mul(p, big.NewInt(2))
	p.Add(p, one)
	return p
}

// return p, q, p_prime, q_prime, err
func GenerateGroupSubgroup(l_p_q_prime int, B int, t int, oddprimes []*big.Int) (*big.Int, *big.Int, *big.Int, *big.Int, error) {
	prime_pricision := 20
	for {
		p_prime, err := generateAPrime(l_p_q_prime)

		if err != nil {
			panic(err)
		}

		ps, err := GenerateDistinctOddPrimes(t, 1<<B, oddprimes)
		if err != nil {
			panic(err)
		}

		p := calculateBigPrime(p_prime, ps)

		if !p.ProbablyPrime(prime_pricision) {
			continue
		}

		fmt.Println("p: ", p.BitLen())
		for {
			q_prime, err := generateAPrime(l_p_q_prime)
			if err != nil {
				panic(err)
			}
			if q_prime.Cmp(p_prime) == 0 {
				continue
			}

			qs, err := GenerateDistinctOddPrimes(t, 1<<B, oddprimes)
			if err != nil {
				panic(err)
			}

			q := calculateBigPrime(q_prime, qs)
			if q.ProbablyPrime(prime_pricision) {
				return p, q, p_prime, q_prime, nil
			}
		}
	}
}
